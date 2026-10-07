# frozen_string_literal: true

module Rack
  class Attack
    class Throttle
      MANDATORY_OPTIONS = [:limit, :period].freeze
      COUNT_ON_MODES = [:request, :response].freeze
      COUNT_WINDOWS = [:start, :finish].freeze

      attr_reader :name, :limit, :period, :block, :type, :count_on, :count_window, :response_classifier

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
        unless COUNT_ON_MODES.include?(@count_on)
          raise ArgumentError, "Invalid :count_on option #{@count_on.inspect}; must be one of #{COUNT_ON_MODES.inspect}"
        end

        if response_counting?
          @response_classifier = options[:classify_response]
          unless @response_classifier.respond_to?(:call)
            raise ArgumentError, "Must pass callable :classify_response option when :count_on is :response"
          end

          @count_window = options.fetch(:count_window, :start)
          unless COUNT_WINDOWS.include?(@count_window)
            raise ArgumentError, "Invalid :count_window option #{@count_window.inspect}; " \
              "must be one of #{COUNT_WINDOWS.inspect}"
          end

          @error_classifications = {
            app: options.fetch(:on_app_error, false),
            body: options.fetch(:on_body_error, false),
            classifier: options.fetch(:on_classifier_error, false)
          }
        end
      end

      def cache
        Rack::Attack.cache
      end

      def response_counting?
        @count_on == :response
      end

      # Classification used when no normal response classification is
      # possible: the app raised (:app), the response body raised while
      # streaming (:body), or the classifier itself raised (:classifier).
      # Each option is either a boolean or a callable taking
      # (request, error).
      def error_classification(kind, request, error)
        value = @error_classifications[kind]
        value.respond_to?(:call) ? !!value.call(request, error) : !!value
      end

      def matched_by?(request)
        discriminator = discriminator_for(request)
        return false unless discriminator

        current_period  = period_for(request)
        current_limit   = limit_for(request)

        if response_counting?
          return matched_by_response_counting?(request, discriminator, current_period, current_limit)
        end

        count = cache.count("#{name}:#{discriminator}", current_period)

        data = {
          discriminator: discriminator,
          count: count,
          period: current_period,
          limit: current_limit,
          epoch_time: cache.last_epoch_time
        }

        annotate_request_with_throttle_data(request, data)

        (count > current_limit).tap do |throttled|
          if throttled
            annotate_request_with_matched_data(request, data)
            Rack::Attack.instrument(request)
          end
        end
      end

      private

      # Response classification counting mode: the request is checked
      # against the number of already completed, classified counts without
      # incrementing anything. Whether this request counts is decided
      # after the app responds, by the :classify_response classifier (see
      # Rack::Attack::ResponseCounter). Note this means requests that are
      # already in flight concurrently are not held to a strict limit;
      # only settled responses consume quota.
      def matched_by_response_counting?(request, discriminator, current_period, current_limit)
        epoch_time = Time.now.to_i
        count = cache.peek_count("#{name}:#{discriminator}", current_period, epoch_time: epoch_time)

        data = {
          discriminator: discriminator,
          count: count,
          period: current_period,
          limit: current_limit,
          epoch_time: epoch_time
        }

        annotate_request_with_throttle_data(request, data)

        if count >= current_limit
          annotate_request_with_matched_data(request, data)
          Rack::Attack.instrument(request)
          true
        else
          register_pending_count(request, discriminator, current_period, epoch_time)
          false
        end
      end

      def register_pending_count(request, discriminator, period, epoch_time)
        counter = ResponseCounter.new(self, request, discriminator, period, epoch_time)
        (request.env['rack.attack.response_counters'] ||= []) << counter
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
