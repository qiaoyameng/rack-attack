# frozen_string_literal: true

module Rack
  class Attack
    class Check
      DEFAULT_ANNOTATION_PREFIX = 'rack.attack'

      attr_reader :name, :block, :type

      def initialize(name = nil, options = {}, annotation_prefix: DEFAULT_ANNOTATION_PREFIX, &block)
        @name = name
        @block = block
        @type = options.fetch(:type, nil)
        @annotation_prefix = annotation_prefix
      end

      def matched_by?(request, instrument: true)
        block.call(request).tap do |match|
          if match
            request.env["#{@annotation_prefix}.matched"] = name
            request.env["#{@annotation_prefix}.match_type"] = type
            Rack::Attack.instrument(request) if instrument
          end
        end
      end
    end
  end
end
