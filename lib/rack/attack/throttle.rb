# frozen_string_literal: true

module Rack
  class Attack
    class Throttle
      MANDATORY_OPTIONS = [:limit, :period].freeze
      COUNT_ON_VALUES = [:request, :response].freeze
      COUNT_WINDOW_VALUES = [:start, :finish].freeze
      ERROR_CLASSIFICATION_VALUES = [:count, :skip].freeze

      # Snapshot of a response passed to response classifiers. The body is
      # deliberately not exposed: bodies must stream through untouched and
      # are never read for classification.
      class Response
        attr_reader :status, :headers

        def initialize(status, headers)
          @status = status
          @headers = headers
        end
      end

      # A response-mode count that has been registered at request entry and
      # is settled exactly once when the response terminates.
      PendingResponseCount = Struct.new(:throttle, :discriminator, :period, :epoch_time)

      attr_reader :name, :limit, :period, :block, :type

      def initialize(name, options, &block)
        @name = name
        @block = block
        MANDATORY_OPTIONS.each do |opt|
          raise ArgumentError, "Must pass #{opt.inspect} option" unless options[opt]
        end
        @limit = options[:limit]
        @period = options[:period].respond_to?(:call) ? options[:period] : options[:period].to_i
        @type   = options.fetch(:type, :throttle)

        @count_on = options.fetch(:count_on, :request)
        unless COUNT_ON_VALUES.include?(@count_on)
          raise ArgumentError, "Must pass :count_on option in #{COUNT_ON_VALUES.inspect}"
        end

        return unless count_on_response?

        @response_classifier = options[:classify_response]
        unless @response_classifier.respond_to?(:call)
          raise ArgumentError, "Must pass a callable :classify_response option when :count_on is :response"
        end

        @count_window = options.fetch(:count_window, :start)
        unless COUNT_WINDOW_VALUES.include?(@count_window)
          raise ArgumentError, "Must pass :count_window option in #{COUNT_WINDOW_VALUES.inspect}"
        end

        @app_error_classification        = error_classification_option(options, :on_app_error)
        @body_error_classification       = error_classification_option(options, :on_body_error)
        @classifier_error_classification = error_classification_option(options, :on_classifier_error)
      end

      def cache
        Rack::Attack.cache
      end

      def count_on_response?
        @count_on == :response
      end

      def matched_by?(request)
        discriminator = discriminator_for(request)
        return false unless discriminator

        current_period  = period_for(request)
        current_limit   = limit_for(request)
        epoch_time      = count_window_start? ? Time.now : nil
        unprefixed_key  = "#{name}:#{discriminator}"

        count =
          if count_on_response?
            # Only failures whose responses already completed are counted.
            cache.current_count(unprefixed_key, current_period, epoch_time: epoch_time)
          else
            cache.count(unprefixed_key, current_period, epoch_time: epoch_time)
          end

        data = {
          discriminator: discriminator,
          count: count,
          period: current_period,
          limit: current_limit,
          epoch_time: cache.last_epoch_time
        }

        annotate_request_with_throttle_data(request, data)

        throttled =
          if count_on_response?
            count >= current_limit
          else
            count > current_limit
          end

        throttled.tap do |matched|
          if matched
            annotate_request_with_matched_data(request, data)
            Rack::Attack.instrument(request)
          elsif count_on_response?
            register_pending_response_count(request, discriminator, current_period, epoch_time)
          end
        end
      end

      # Settles the pending count for a normally completed response. The
      # classifier runs exactly once, when the response terminates.
      def count_response!(pending, request, response)
        counted =
          begin
            !!@response_classifier.call(request, response)
          rescue StandardError => e
            error_classification_counted?(@classifier_error_classification, request, e)
          end

        increment_pending_count(pending) if counted
      end

      # Settles the pending count when the application raised.
      def count_app_error!(pending, request, exception)
        if error_classification_counted?(@app_error_classification, request, exception)
          increment_pending_count(pending)
        end
      end

      # Settles the pending count when the response body raised while streaming.
      def count_body_error!(pending, request, exception)
        if error_classification_counted?(@body_error_classification, request, exception)
          increment_pending_count(pending)
        end
      end

      private

      def count_window_start?
        count_on_response? && @count_window == :start
      end

      def register_pending_response_count(request, discriminator, period, epoch_time)
        pending = PendingResponseCount.new(self, discriminator, period, epoch_time)
        (request.env['rack.attack.pending_response_counts'] ||= []) << pending
      end

      def increment_pending_count(pending)
        cache.count("#{name}:#{pending.discriminator}", pending.period, epoch_time: pending.epoch_time)
      end

      def error_classification_option(options, key)
        classification = options.fetch(key, :skip)
        if ERROR_CLASSIFICATION_VALUES.include?(classification) || classification.respond_to?(:call)
          return classification
        end

        raise ArgumentError, "Must pass #{key.inspect} option in #{ERROR_CLASSIFICATION_VALUES.inspect} or a callable"
      end

      def error_classification_counted?(classification, request, exception)
        case classification
        when :count then true
        when :skip then false
        else !!classification.call(request, exception)
        end
      end

      def discriminator_for(request)
        discriminator = block.call(request)
        if discriminator && Rack::Attack.throttle_discriminator_normalizer
          discriminator = Rack::Attack.throttle_discriminator_normalizer.call(discriminator)
        end
        discriminator
      end

      def period_for(request)
        period.respond_to?(:call) ? period.call(request) : period
      end

      def limit_for(request)
        limit.respond_to?(:call) ? limit.call(request) : limit
      end

      def annotate_request_with_throttle_data(request, data)
        (request.env['rack.attack.throttle_data'] ||= {})[name] = data
      end

      def annotate_request_with_matched_data(request, data)
        request.env['rack.attack.matched']             = name
        request.env['rack.attack.match_discriminator'] = data[:discriminator]
        request.env['rack.attack.match_type']          = type
        request.env['rack.attack.match_data']          = data
      end
    end
  end
end
