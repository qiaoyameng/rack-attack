# frozen_string_literal: true

require 'rack'
require 'forwardable'
require 'rack/attack/cache'
require 'rack/attack/configuration'
require 'rack/attack/path_normalizer'
require 'rack/attack/request'
require 'rack/attack/store_proxy/dalli_proxy'
require 'rack/attack/store_proxy/mem_cache_store_proxy'
require 'rack/attack/store_proxy/redis_proxy'
require 'rack/attack/store_proxy/redis_store_proxy'
require 'rack/attack/store_proxy/redis_cache_store_proxy'

require 'rack/attack/railtie' if defined?(::Rails)

module Rack
  class Attack
    class Error < StandardError; end

    class MisconfiguredStoreError < Error; end

    class MissingStoreError < Error; end

    class IncompatibleStoreError < Error; end

    autoload :Check,                'rack/attack/check'
    autoload :Throttle,             'rack/attack/throttle'
    autoload :Safelist,             'rack/attack/safelist'
    autoload :Blocklist,            'rack/attack/blocklist'
    autoload :Track,                'rack/attack/track'
    autoload :ShadowConfiguration,  'rack/attack/shadow_configuration'
    autoload :Fail2Ban,             'rack/attack/fail2ban'
    autoload :Allow2Ban,            'rack/attack/allow2ban'

    class << self
      attr_accessor :enabled, :notifier, :throttle_discriminator_normalizer
      attr_reader :configuration
      attr_writer :shadow

      def instrument(request)
        # Shadow evaluation only emits decision records, never notifications.
        return if Thread.current[:rack_attack_shadow_cache]

        if notifier
          event_type = request.env["rack.attack.match_type"]
          notifier.instrument("#{event_type}.rack_attack", request: request)

          # Deprecated: Keeping just for backwards compatibility
          notifier.instrument("rack.attack", request: request)
        end
      end

      def cache
        @cache ||= Cache.new
      end

      # The cache seen by throttles and ban filters. During shadow evaluation
      # this is the shadow cache, so shadow counters use their own namespace.
      def current_cache
        Thread.current[:rack_attack_shadow_cache] || cache
      end

      def with_shadow_cache(shadow_cache)
        previous = Thread.current[:rack_attack_shadow_cache]
        Thread.current[:rack_attack_shadow_cache] = shadow_cache
        yield
      ensure
        Thread.current[:rack_attack_shadow_cache] = previous
      end

      def shadow
        @shadow ||= ShadowConfiguration.new
      end

      def shadow_configured?
        !@shadow.nil?
      end

      def clear!
        warn "[DEPRECATION] Rack::Attack.clear! is deprecated. Please use Rack::Attack.clear_configuration instead"
        @configuration.clear_configuration
      end

      def reset!
        cache.reset!
      end

      extend Forwardable
      def_delegators(
        :@configuration,
        :safelist,
        :blocklist,
        :blocklist_ip,
        :safelist_ip,
        :throttle,
        :track,
        :throttled_responder,
        :throttled_responder=,
        :blocklisted_responder,
        :blocklisted_responder=,
        :blocklisted_response,
        :blocklisted_response=,
        :throttled_response,
        :throttled_response=,
        :throttled_response_retry_after_header,
        :throttled_response_retry_after_header=,
        :clear_configuration,
        :safelists,
        :blocklists,
        :throttles,
        :tracks
      )
    end

    # Set defaults
    @enabled = true
    @notifier = ActiveSupport::Notifications if defined?(ActiveSupport::Notifications)
    @throttle_discriminator_normalizer = lambda do |discriminator|
      discriminator.to_s.strip.downcase
    end
    @configuration = Configuration.new

    attr_reader :configuration

    def initialize(app)
      @app = app
      @configuration = self.class.configuration
    end

    def call(env)
      return @app.call(env) if !self.class.enabled || env["rack.attack.called"]

      env["rack.attack.called"] = true
      env['PATH_INFO'] = PathNormalizer.normalize_path(env['PATH_INFO'])
      request = Rack::Attack::Request.new(env)

      config = configuration
      # Snapshot the shadow rules once per request, so a hot config swap
      # cannot make this request mix old and new rule versions.
      shadow_snapshot = nil
      if self.class.shadow_configured?
        shadow_snapshot = self.class.shadow.snapshot
        # Shadow rules must observe the same request facts as the primary
        # rules, so the input has to be rewindable even where the server
        # does not provide a rewindable rack.input.
        if env['rack.input'] && !env['rack.input'].respond_to?(:rewind)
          env['rack.input'] = Rack::RewindableInput.new(env['rack.input'])
        end
      end

      decision =
        if config.safelisted?(request)
          :safelisted
        elsif config.blocklisted?(request)
          :blocklisted
        elsif config.throttled?(request)
          :throttled
        else
          config.tracked?(request)
          :proceed
        end

      # The shadow rules always evaluate the same request facts in full, even
      # when the primary configuration returned early.
      shadow_snapshot.evaluate(request) if shadow_snapshot

      if decision == :blocklisted
        # Deprecated: Keeping blocklisted_response for backwards compatibility
        if config.blocklisted_response
          config.blocklisted_response.call(env)
        else
          config.blocklisted_responder.call(request)
        end
      elsif decision == :throttled
        # Deprecated: Keeping throttled_response for backwards compatibility
        if config.throttled_response
          config.throttled_response.call(env)
        else
          config.throttled_responder.call(request)
        end
      else
        @app.call(env)
      end
    end
  end
end
