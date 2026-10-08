# frozen_string_literal: true

require 'rack'
require 'forwardable'
require 'rack/attack/cache'
require 'rack/attack/configuration'
require 'rack/attack/path_normalizer'
require 'rack/attack/request'
require 'rack/attack/request_snapshot'
require 'rack/attack/shadow'
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
    autoload :Fail2Ban,             'rack/attack/fail2ban'
    autoload :Allow2Ban,            'rack/attack/allow2ban'

    SHADOW_ANNOTATION_PREFIX = 'rack.attack.shadow'

    class << self
      attr_accessor :enabled, :notifier, :throttle_discriminator_normalizer
      attr_reader :configuration, :shadow_configuration, :shadow_recorder

      def instrument(request)
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

      # Cache used by rules currently being evaluated. Shadow evaluation swaps
      # in its own cache via .with_cache so counters live in a separate
      # namespace without changing how production rules count.
      def current_cache
        Thread.current[:rack_attack_cache] || cache
      end

      def with_cache(cache)
        previous = Thread.current[:rack_attack_cache]
        Thread.current[:rack_attack_cache] = cache
        yield
      ensure
        Thread.current[:rack_attack_cache] = previous
      end

      def clear!
        warn "[DEPRECATION] Rack::Attack.clear! is deprecated. Please use Rack::Attack.clear_configuration instead"
        @configuration.clear_configuration
      end

      def reset!
        cache.reset!
      end

      def shadow(&block)
        self.shadow_configuration = Configuration.new(annotation_prefix: SHADOW_ANNOTATION_PREFIX)
        shadow_configuration.instance_eval(&block) if block
        shadow_configuration
      end

      def shadow_configuration=(configuration)
        @shadow_configuration = configuration
      end

      def shadow_cache
        @shadow_cache ||= begin
          shadow = Cache.new
          shadow.prefix = 'rack::attack-shadow'
          shadow
        end
      end

      def shadow_cache=(cache)
        shadow =
          if cache.is_a?(Cache)
            cache
          else
            Cache.new(store: cache)
          end
        shadow.prefix = 'rack::attack-shadow'
        @shadow_cache = shadow
      end

      def shadow_recorder=(recorder)
        raise ArgumentError, "shadow_recorder must respond to #call" if recorder && !recorder.respond_to?(:call)

        @shadow_recorder = recorder
      end

      def clear_shadow_configuration
        @shadow_configuration = nil
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

      # Pin both rule sets for the whole request so a hot configuration swap
      # cannot make the first half of one request use the old version and the
      # second half the new one.
      configuration = self.class.configuration
      shadow_configuration = self.class.shadow_configuration

      # Request facts (including the normalized path and request body) are
      # captured once inside the shadow evaluation; production rules keep
      # reading the untouched, live request.
      if shadow_configuration
        safely_evaluate_shadow(request, shadow_configuration)
      end

      if configuration.safelisted?(request)
        @app.call(env)
      elsif configuration.blocklisted?(request)
        # Deprecated: Keeping blocklisted_response for backwards compatibility
        if configuration.blocklisted_response
          configuration.blocklisted_response.call(env)
        else
          configuration.blocklisted_responder.call(request)
        end
      elsif configuration.throttled?(request)
        # Deprecated: Keeping throttled_response for backwards compatibility
        if configuration.throttled_response
          configuration.throttled_response.call(env)
        else
          configuration.throttled_responder.call(request)
        end
      else
        configuration.tracked?(request)
        @app.call(env)
      end
    end

    private

    def safely_evaluate_shadow(request, shadow_configuration)
      Shadow.evaluate(
        request,
        shadow_configuration,
        self.class.shadow_cache,
        shadow_configuration.version,
        self.class.shadow_recorder
      )
    rescue StandardError => e
      warn "[rack-attack] shadow evaluation failed: #{e.class}: #{e.message}"
      begin
        record = {
          verdict: :unknown,
          reason: 'error',
          rule_version: shadow_configuration.version,
          configuration_version: shadow_configuration.version,
          request: {
            path: request.path,
            request_method: request.request_method,
            ip: request.ip
          },
          error: "#{e.class}: #{e.message}"
        }
        recorder = self.class.shadow_recorder
        if recorder
          recorder.call(record) rescue nil
        elsif (notifier = self.class.notifier)
          notifier.instrument('shadow.rack_attack', record)
        end
      rescue StandardError
        nil
      end
    end
  end
end
