# frozen_string_literal: true

module Rack
  class Attack
    # Evaluates a configuration in "shadow mode": the same request facts are
    # run through the full rule set, but the verdict is only recorded - it
    # never influences the response. Counters live in their own cache
    # namespace and annotations live under rack.attack.shadow.* keys so they
    # can never overwrite the production evaluation.
    class Shadow
      ANNOTATION_KEYS = %w[
        rack.attack.shadow.matched
        rack.attack.shadow.match_type
        rack.attack.shadow.match_discriminator
        rack.attack.shadow.match_data
        rack.attack.shadow.throttle_data
      ].freeze

      class << self
        def evaluate(request, configuration, cache, version, recorder)
          snapshot = RequestSnapshot.capture(request)
          shadow_env = snapshot.to_env
          shadow_request = Rack::Attack::Request.new(shadow_env)
          record = build_record(request, configuration, version)

          verdict, reason = begin
            Rack::Attack.with_cache(cache) do
              evaluate_rules(shadow_request, configuration)
            end
          rescue StandardError => e
            record[:error] = "#{e.class}: #{e.message}"
            [:unknown, 'error']
          end

          finalize_record(record, shadow_env, verdict, reason)
          record
        ensure
          emit_record(record, recorder)
        end

        private

        def evaluate_rules(shadow_request, configuration)
          if configuration.safelisted?(shadow_request, instrument: false)
            [:allow, 'safelist']
          elsif configuration.blocklisted?(shadow_request, instrument: false)
            [:block, 'blocklist']
          elsif configuration.throttled?(shadow_request, instrument: false)
            [:throttle, 'throttle']
          else
            configuration.tracked?(shadow_request, instrument: false)
            [:allow, 'no_match']
          end
        end

        def build_record(request, configuration, version)
          {
            verdict: nil,
            reason: nil,
            rule_version: version,
            configuration_version: configuration.version,
            request: {
              path: request.path,
              request_method: request.request_method,
              ip: request.ip
            },
            matched: nil,
            match_type: nil,
            discriminator: nil,
            match_data: nil,
            evaluated_at: Time.now.to_i
          }
        end

        def finalize_record(record, shadow_env, verdict, reason)
          record[:verdict] = verdict
          record[:reason] = reason
          record[:matched] = shadow_env['rack.attack.shadow.matched']
          record[:match_type] = shadow_env['rack.attack.shadow.match_type']
          record[:discriminator] = shadow_env['rack.attack.shadow.match_discriminator']
          record[:match_data] = shadow_env['rack.attack.shadow.match_data']
        end

        def emit_record(record, recorder)
          return unless record

          if recorder
            begin
              recorder.call(record)
            rescue StandardError => e
              warn "[rack-attack] shadow recorder failed: #{e.class}: #{e.message}"
              record[:verdict] = :unknown
              record[:reason] = 'recorder_error'
              default_emit(record)
            end
          else
            default_emit(record)
          end
        end

        def default_emit(record)
          notifier = Rack::Attack.notifier
          return unless notifier

          notifier.instrument('shadow.rack_attack', record)
        rescue StandardError => e
          warn "[rack-attack] shadow notification failed: #{e.class}: #{e.message}"
        end
      end
    end
  end
end
