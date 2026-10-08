# frozen_string_literal: true

module Rack
  class Attack
    class Throttle
      MANDATORY_OPTIONS = [:limit, :period].freeze

      attr_reader :name, :limit, :period, :block, :type

      def initialize(name, options, annotation_prefix: Check::DEFAULT_ANNOTATION_PREFIX, &block)
        @name = name
        @block = block
        @annotation_prefix = annotation_prefix
        MANDATORY_OPTIONS.each do |opt|
          raise ArgumentError, "Must pass #{opt.inspect} option" unless options[opt]
        end
        @limit = options[:limit]
        @period = options[:period].respond_to?(:call) ? options[:period] : options[:period].to_i
        @type   = options.fetch(:type, :throttle)
      end

      def cache
        Rack::Attack.current_cache
      end

      def matched_by?(request, instrument: true)
        discriminator = discriminator_for(request)
        return false unless discriminator

        current_period  = period_for(request)
        current_limit   = limit_for(request)
        count           = cache.count("#{name}:#{discriminator}", current_period)

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
            Rack::Attack.instrument(request) if instrument
          end
        end
      end

      private

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
        key = "#{@annotation_prefix}.throttle_data"
        (request.env[key] ||= {})[name] = data
      end

      def annotate_request_with_matched_data(request, data)
        request.env["#{@annotation_prefix}.matched"]             = name
        request.env["#{@annotation_prefix}.match_discriminator"] = data[:discriminator]
        request.env["#{@annotation_prefix}.match_type"]          = type
        request.env["#{@annotation_prefix}.match_data"]          = data
      end
    end
  end
end
