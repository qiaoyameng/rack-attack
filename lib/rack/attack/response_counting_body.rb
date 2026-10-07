# frozen_string_literal: true

module Rack
  class Attack
    # Wraps the application response body when one or more throttles use
    # `count_on: :response`. Chunks stream through untouched; the body is
    # never buffered or read ahead for classification. The first terminal
    # event (body fully streamed, body raising while streaming, or close)
    # settles every pending response count exactly once.
    class ResponseCountingBody
      def initialize(body, request, response)
        @body = body
        @request = request
        @response = response
      end

      def each(&block)
        return enum_for(:each) unless block_given?

        begin
          @body.each(&block)
        rescue StandardError => e
          settle { |pending| pending.throttle.count_body_error!(pending, @request, e) }
          raise
        end

        settle { |pending| pending.throttle.count_response!(pending, @request, @response) }
      end

      def close
        settle { |pending| pending.throttle.count_response!(pending, @request, @response) }
        @body.close if @body.respond_to?(:close)
      end

      private

      def settle
        Rack::Attack.drain_pending_response_counts(@request).each do |pending|
          yield pending
        end
      end
    end
  end
end
