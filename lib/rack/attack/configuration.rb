# frozen_string_literal: true

require "ipaddr"

module Rack
  class Attack
    class Configuration
      DEFAULT_BLOCKLISTED_RESPONDER = lambda { |_req| [403, { 'content-type' => 'text/plain' }, ["Forbidden\n"]] }

      DEFAULT_THROTTLED_RESPONDER = lambda do |req|
        if Rack::Attack.configuration.throttled_response_retry_after_header
          match_data = req.env['rack.attack.match_data']
          now = match_data[:epoch_time]
          retry_after = match_data[:period] - (now % match_data[:period])

          [429, { 'content-type' => 'text/plain', 'retry-after' => retry_after.to_s }, ["Retry later\n"]]
        else
          [429, { 'content-type' => 'text/plain' }, ["Retry later\n"]]
        end
      end

      class << self
        def next_version
          @version_counter = (@version_counter || 0) + 1
        end
      end

      attr_reader :safelists, :blocklists, :throttles, :tracks, :anonymous_blocklists, :anonymous_safelists
      attr_reader :version, :annotation_prefix
      attr_accessor :blocklisted_responder, :throttled_responder, :throttled_response_retry_after_header

      attr_reader :blocklisted_response, :throttled_response # Keeping these for backwards compatibility

      def blocklisted_response=(responder)
        warn "[DEPRECATION] Rack::Attack.blocklisted_response is deprecated. "\
          "Please use Rack::Attack.blocklisted_responder instead."
        @blocklisted_response = responder
      end

      def throttled_response=(responder)
        warn "[DEPRECATION] Rack::Attack.throttled_response is deprecated. "\
          "Please use Rack::Attack.throttled_responder instead"
        @throttled_response = responder
      end

      def initialize(annotation_prefix: 'rack.attack')
        @annotation_prefix = annotation_prefix
        set_defaults
      end

      def safelist(name = nil, &block)
        safelist = Safelist.new(name, annotation_prefix: annotation_prefix, &block)

        if name
          @safelists[name] = safelist
        else
          @anonymous_safelists << safelist
        end
      end

      def blocklist(name = nil, &block)
        blocklist = Blocklist.new(name, annotation_prefix: annotation_prefix, &block)

        if name
          @blocklists[name] = blocklist
        else
          @anonymous_blocklists << blocklist
        end
      end

      def blocklist_ip(ip_address)
        @anonymous_blocklists << Blocklist.new(annotation_prefix: annotation_prefix) do |request|
          request.ip && !request.ip.empty? && IPAddr.new(ip_address).include?(IPAddr.new(request.ip))
        end
      end

      def safelist_ip(ip_address)
        @anonymous_safelists << Safelist.new(annotation_prefix: annotation_prefix) do |request|
          request.ip && !request.ip.empty? && IPAddr.new(ip_address).include?(IPAddr.new(request.ip))
        end
      end

      def throttle(name, options, &block)
        @throttles[name] = Throttle.new(name, options, annotation_prefix: annotation_prefix, &block)
      end

      def track(name, options = {}, &block)
        @tracks[name] = Track.new(name, options, annotation_prefix: annotation_prefix, &block)
      end

      def safelisted?(request, instrument: true)
        @anonymous_safelists.any? { |safelist| safelist.matched_by?(request, instrument: instrument) } ||
          @safelists.any? { |_name, safelist| safelist.matched_by?(request, instrument: instrument) }
      end

      def blocklisted?(request, instrument: true)
        @anonymous_blocklists.any? { |blocklist| blocklist.matched_by?(request, instrument: instrument) } ||
          @blocklists.any? { |_name, blocklist| blocklist.matched_by?(request, instrument: instrument) }
      end

      def throttled?(request, instrument: true)
        @throttles.any? do |_name, throttle|
          throttle.matched_by?(request, instrument: instrument)
        end
      end

      def tracked?(request, instrument: true)
        @tracks.each_value do |track|
          track.matched_by?(request, instrument: instrument)
        end
      end

      def clear_configuration
        set_defaults
      end

      private

      def set_defaults
        @safelists = {}
        @blocklists = {}
        @throttles = {}
        @tracks = {}
        @anonymous_blocklists = []
        @anonymous_safelists = []
        @throttled_response_retry_after_header = false
        @version = self.class.next_version

        @blocklisted_responder = DEFAULT_BLOCKLISTED_RESPONDER
        @throttled_responder = DEFAULT_THROTTLED_RESPONDER

        # Deprecated: Keeping these for backwards compatibility
        @blocklisted_response = nil
        @throttled_response = nil
      end
    end
  end
end
