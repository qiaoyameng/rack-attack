# frozen_string_literal: true

module Rack
  class Attack
    # ShadowConfiguration is an independent rule set that observes the same
    # request facts as the primary configuration, counts in its own cache
    # namespace, and only emits decision records. It never influences the
    # response, which is always determined by the primary configuration.
    #
    #   Rack::Attack.shadow.throttle("logins/ip", limit: 5, period: 60) { |req| req.ip }
    #   Rack::Attack.shadow.recorder = ->(decision) { MyLogger.log(decision) }
    class ShadowConfiguration < Configuration
      # Env keys Rack::Attack uses to annotate a request. They are stashed
      # before shadow evaluation and restored afterwards, so neither
      # configuration can overwrite the other's annotations.
      ANNOTATION_KEYS = %w[
        rack.attack.matched
        rack.attack.match_type
        rack.attack.match_discriminator
        rack.attack.match_data
        rack.attack.throttle_data
      ].freeze

      # The outcome of a shadow evaluation for a single request. +decision+ is
      # one of :safelisted, :blocklisted, :throttled, :passed, or :unknown
      # (when the shadow store or evaluation failed; never silently :passed).
      class Decision
        attr_reader :version, :request
        attr_accessor :decision, :matched, :match_type, :match_data, :error

        def initialize(version, request)
          @version = version
          @request = request
          @decision = :unknown
          @error = nil
        end

        def unknown?
          decision == :unknown
        end
      end

      # An immutable view of the shadow rules captured once per request, so a
      # hot config swap cannot make one request mix old and new rule versions.
      class Snapshot < Configuration
        attr_reader :version, :cache

        def initialize(version:, recorder:, cache:, rules:)
          super()
          @version = version
          @recorder = recorder
          @cache = cache
          @safelists = rules[:safelists]
          @blocklists = rules[:blocklists]
          @throttles = rules[:throttles]
          @tracks = rules[:tracks]
          @anonymous_safelists = rules[:anonymous_safelists]
          @anonymous_blocklists = rules[:anonymous_blocklists]
        end

        def evaluate(request)
          record = Decision.new(version, request)
          env = request.env
          stash = stash_annotations(env)

          begin
            rewind_input(env)
            Rack::Attack.with_shadow_cache(cache) do
              evaluate_rules(request, record)
            end
          rescue StandardError => e
            record.decision = :unknown
            record.error = e
          ensure
            restore_annotations(env, stash)
            rewind_input(env)
          end

          deliver(record)
          record
        end

        private

        def evaluate_rules(request, record)
          record.decision =
            if safelisted?(request)
              :safelisted
            elsif blocklisted?(request)
              :blocklisted
            elsif throttled?(request)
              :throttled
            else
              tracked?(request)
              :passed
            end

          env = request.env
          record.matched = env['rack.attack.matched']
          record.match_type = env['rack.attack.match_type']
          record.match_data = env['rack.attack.match_data']
        end

        def stash_annotations(env)
          ANNOTATION_KEYS.each_with_object({}) do |key, stash|
            stash[key] = env.delete(key)
          end
        end

        def restore_annotations(env, stash)
          ANNOTATION_KEYS.each { |key| env.delete(key) }
          stash.each { |key, value| env[key] = value unless value.nil? }
        end

        def rewind_input(env)
          input = env['rack.input']
          input.rewind if input && input.respond_to?(:rewind)
        rescue StandardError
          nil
        end

        def deliver(record)
          @recorder.call(record) if @recorder
        rescue StandardError => e
          warn "[rack-attack] Shadow recorder failed: #{e.class}: #{e.message}"
        end
      end

      attr_writer :cache, :recorder

      def initialize
        super
        @revision = 0
        @explicit_version = nil
        @recorder = nil
        @cache = nil
      end

      # The rule version attached to every decision record. Defaults to an
      # internal revision bumped on every rule change; assign your own version
      # (e.g. a deploy id) to override it.
      def version
        @explicit_version || @revision
      end

      def version=(version)
        @explicit_version = version
      end

      def recorder
        @recorder
      end

      # Counts in its own namespace derived from the primary cache, so shadow
      # counters never collide with primary ones. Assign a custom
      # Rack::Attack::Cache to fully isolate the shadow store.
      def cache
        @cache ||= default_cache
      end

      def snapshot
        Snapshot.new(
          version: version,
          recorder: @recorder,
          cache: cache,
          rules: {
            safelists: @safelists.dup,
            blocklists: @blocklists.dup,
            throttles: @throttles.dup,
            tracks: @tracks.dup,
            anonymous_safelists: @anonymous_safelists.dup,
            anonymous_blocklists: @anonymous_blocklists.dup
          }
        )
      end

      def safelist(name = nil, &block)
        super.tap { bump_revision }
      end

      def blocklist(name = nil, &block)
        super.tap { bump_revision }
      end

      def blocklist_ip(ip_address)
        super.tap { bump_revision }
      end

      def safelist_ip(ip_address)
        super.tap { bump_revision }
      end

      def throttle(name, options, &block)
        super.tap { bump_revision }
      end

      def track(name, options = {}, &block)
        super.tap { bump_revision }
      end

      def clear_configuration
        super.tap { bump_revision }
      end

      private

      def bump_revision
        @revision += 1
      end

      def default_cache
        primary = Rack::Attack.cache
        Cache.new(store: primary.store).tap do |shadow_cache|
          shadow_cache.prefix = "#{primary.prefix}:shadow"
        end
      end
    end
  end
end
