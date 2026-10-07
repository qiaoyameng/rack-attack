# frozen_string_literal: true

module Rack
  class Attack
    class Cache
      attr_accessor :prefix
      attr_reader :last_epoch_time

      def self.default_store
        if Object.const_defined?(:Rails) && Rails.respond_to?(:cache)
          ::Rails.cache
        end
      end

      def initialize(store: self.class.default_store)
        self.store = store
        @prefix = 'rack::attack'
      end

      attr_reader :store

      def store=(store)
        @store =
          if (proxy = BaseProxy.lookup(store))
            proxy.new(store)
          else
            store
          end
        if @store
          check_store_methods_presence(:read, :write, :delete, :increment)
        end
      end

      def count(unprefixed_key, period, epoch_time: nil)
        key, expires_in = key_and_expiry(unprefixed_key, period, epoch_time)
        do_count(key, expires_in)
      end

      # Returns the current count for the given key and period without
      # incrementing it. Used by throttles that count classified responses
      # after the app has run, where the check at request time must not
      # consume quota itself.
      def peek_count(unprefixed_key, period, epoch_time: nil)
        raise Rack::Attack::MissingStoreError if store.nil?

        key, _expires_in = key_and_expiry(unprefixed_key, period, epoch_time)
        value = store.read(key)
        value ? value.to_i : 0
      end

      def read(unprefixed_key)
        raise Rack::Attack::MissingStoreError if store.nil?

        store.read("#{prefix}:#{unprefixed_key}")
      end

      def write(unprefixed_key, value, expires_in)
        raise Rack::Attack::MissingStoreError if store.nil?

        store.write("#{prefix}:#{unprefixed_key}", value, expires_in: expires_in)
      end

      def reset_count(unprefixed_key, period)
        key, _ = key_and_expiry(unprefixed_key, period)
        store.delete(key)
      end

      def delete(unprefixed_key)
        store.delete("#{prefix}:#{unprefixed_key}")
      end

      def reset!
        if store.respond_to?(:delete_matched)
          store.delete_matched(/#{prefix}*/)
        else
          raise(
            Rack::Attack::IncompatibleStoreError,
            "Configured store #{store.class.name} doesn't respond to #delete_matched method"
          )
        end
      end

      private

      def key_and_expiry(unprefixed_key, period, epoch_time = nil)
        @last_epoch_time = (epoch_time || Time.now.to_i).to_i
        # Add 1 to expires_in to avoid timing error: https://github.com/rack/rack-attack/pull/85
        expires_in = (period - (@last_epoch_time % period) + 1).to_i
        # An explicitly passed epoch_time may belong to a window that is
        # (almost) over; never write with a non-positive expiry.
        expires_in = 1 if expires_in < 1
        ["#{prefix}:#{(@last_epoch_time / period).to_i}:#{unprefixed_key}", expires_in]
      end

      def do_count(key, expires_in)
        raise Rack::Attack::MissingStoreError if store.nil?

        result = store.increment(key, 1, expires_in: expires_in)

        # NB: Some stores return nil when incrementing uninitialized values
        if result.nil?
          store.write(key, 1, expires_in: expires_in)
        end
        result || 1
      end

      def check_store_methods_presence(*method_names)
        missing = method_names.reject { |m| store.respond_to?(m) }
        unless missing.empty?
          missing = missing.map { |m| "##{m}" }.join(", ")
          warn "[rack-attack] Configured store #{store.class.name} doesn't respond to #{missing}"
        end
      end
    end
  end
end
