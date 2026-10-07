# frozen_string_literal: true

module Rack
  class Attack
    # Tracks a single pending response-classified throttle count for one
    # request. Exactly one settlement happens per counter: either the
    # response is classified by the throttle's classifier, or an error
    # classification decides. The count is only written to the cache when
    # the classification is truthy.
    class ResponseCounter
      def initialize(throttle, request, discriminator, period, epoch_time)
        @throttle = throttle
        @request = request
        @discriminator = discriminator
        @period = period
        @epoch_time = epoch_time
        @settled = false
      end

      def settled?
        @settled
      end

      def settle_response(status, headers)
        return if settled?

        @settled = true

        counted =
          begin
            !!@throttle.response_classifier.call(@request, status, headers)
          rescue => e
            !!@throttle.error_classification(:classifier, @request, e)
          end

        count! if counted
      end

      def settle_error(kind, error)
        return if settled?

        @settled = true

        count! if @throttle.error_classification(kind, @request, error)
      end

      private

      def count!
        epoch_time = @throttle.count_window == :start ? @epoch_time : nil
        @throttle.cache.count("#{@throttle.name}:#{@discriminator}", @period, epoch_time: epoch_time)
      end
    end
  end
end
