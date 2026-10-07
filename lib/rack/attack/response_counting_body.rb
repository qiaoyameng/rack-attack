# frozen_string_literal: true

module Rack
  class Attack
    # Wraps the app's response body so response-classified throttle counts
    # settle when the response has actually been delivered. Chunks stream
    # through untouched; the body is never buffered or read ahead for
    # classification. Settlement happens exactly once per counter: when the
    # body finishes streaming or is closed (whichever comes first), or with
    # the error classification if the body raises midway.
    class ResponseCountingBody
      def initialize(body, counters, status, headers)
        @body = body
        @counters = counters
        @status = status
        @headers = headers
      end

      def each(&block)
        @body.each(&block)
        settle_response
      rescue => e
        settle_error(e)
        raise
      end

      def close
        @body.close if @body.respond_to?(:close)
        settle_response
      end

      def respond_to_missing?(name, include_private = false)
        @body.respond_to?(name, include_private) || super
      end

      def method_missing(name, *args, &block)
        if @body.respond_to?(name)
          @body.public_send(name, *args, &block)
        else
          super
        end
      end

      private

      def settle_response
        @counters.each { |counter| counter.settle_response(@status, @headers) }
      end

      def settle_error(error)
        @counters.each { |counter| counter.settle_error(:body, error) }
      end
    end
  end
end
