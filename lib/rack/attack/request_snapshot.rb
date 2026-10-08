# frozen_string_literal: true

require 'stringio'

module Rack
  class Attack
    # Captures the immutable request "facts" exactly once so that shadow rules
    # can evaluate the same request without consuming the original rack.input
    # or re-collecting anything from the live request.
    class RequestSnapshot
      attr_reader :env

      def self.capture(request)
        env = request.env.dup
        body = read_body(request)
        rewind_input(request)
        new(env, body)
      end

      def initialize(env, body)
        @env = env
        @body = body
      end

      # Returns an isolated copy of the captured facts. The copied env and the
      # fresh input stream never mutate the request that is delivered to the
      # real app.
      def to_env
        env = @env.dup
        env['rack.input'] = StringIO.new(@body.dup)
        env
      end

      def self.read_body(request)
        input = request.env['rack.input']
        return +'' unless input

        input.respond_to?(:read) ? (input.read || +'') : +''
      end
      private_class_method :read_body

      def self.rewind_input(request)
        input = request.env['rack.input']
        input&.rewind if input.respond_to?(:rewind)
      end
      private_class_method :rewind_input
    end
  end
end
