# frozen_string_literal: true

module Rack
  class Attack
    class Track
      attr_reader :filter

      def initialize(name, options = {}, annotation_prefix: Check::DEFAULT_ANNOTATION_PREFIX, &block)
        options[:type] = :track

        @filter =
          if options[:limit] && options[:period]
            Throttle.new(name, options, annotation_prefix: annotation_prefix, &block)
          else
            Check.new(name, options, annotation_prefix: annotation_prefix, &block)
          end
      end

      def matched_by?(request, instrument: true)
        filter.matched_by?(request, instrument: instrument)
      end
    end
  end
end
