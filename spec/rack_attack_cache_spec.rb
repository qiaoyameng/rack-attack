# frozen_string_literal: true

require_relative 'spec_helper'
require 'timecop'

describe 'Rack::Attack::Cache' do
  before do
    @cache = Rack::Attack::Cache.new
    @cache.store = ActiveSupport::Cache::MemoryStore.new
  end

  describe '#peek_count' do
    it 'returns zero for unknown keys' do
      _(@cache.peek_count('key', 60)).must_equal 0
    end

    it 'reads the current count without incrementing it' do
      @cache.count('key', 60)

      _(@cache.peek_count('key', 60)).must_equal 1
      _(@cache.peek_count('key', 60)).must_equal 1
    end

    it 'reads the window of an explicit epoch_time' do
      Timecop.freeze(Time.at(600)) do
        @cache.count('key', 60, epoch_time: 0)

        _(@cache.peek_count('key', 60)).must_equal 0
        _(@cache.peek_count('key', 60, epoch_time: 0)).must_equal 1
      end
    end
  end

  describe '#count with epoch_time' do
    it 'counts into the window of the given epoch time' do
      Timecop.freeze(Time.at(600)) do
        @cache.count('key', 60, epoch_time: 0)

        _(@cache.store.read('rack::attack:0:key')).must_equal 1
        _(@cache.store.read("rack::attack:#{600 / 60}:key")).must_be_nil
      end
    end

    it 'never writes with a non-positive expiry for long-past windows' do
      Timecop.freeze(Time.at(6000)) do
        @cache.count('key', 60, epoch_time: 0)

        _(@cache.store.read('rack::attack:0:key')).must_equal 1
      end
    end
  end
end
