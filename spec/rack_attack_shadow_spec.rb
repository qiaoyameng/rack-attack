# frozen_string_literal: true

require_relative 'spec_helper'
require_relative 'support/freeze_time_helper'

describe 'Rack::Attack shadow configuration' do
  before do
    @store = ActiveSupport::Cache::MemoryStore.new
    Rack::Attack.cache.store = @store
    @records = []
    Rack::Attack.shadow.recorder = ->(record) { @records << record }
  end

  def primary_key(name, discriminator, period)
    "rack::attack:#{Time.now.to_i / period}:#{name}:#{discriminator}"
  end

  def shadow_key(name, discriminator, period)
    "rack::attack:shadow:#{Time.now.to_i / period}:#{name}:#{discriminator}"
  end

  it 'emits a decision record for every request without changing the response' do
    get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

    _(last_response.status).must_equal 200
    _(@records.size).must_equal 1
    _(@records.first.decision).must_equal :passed
    _(@records.first.version).must_equal Rack::Attack.shadow.version
  end

  it 'counts primary and shadow throttles in separate namespaces, response follows primary only' do
    Rack::Attack.throttle('req/ip', limit: 2, period: 60) { |req| req.ip }
    Rack::Attack.shadow.throttle('req/ip', limit: 1, period: 60) { |req| req.ip }

    within_same_period do
      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'
      _(last_response.status).must_equal 200
      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'
      _(last_response.status).must_equal 200
      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'
      _(last_response.status).must_equal 429

      # Three results to compare: primary count, shadow count, actual response.
      _(@store.read(primary_key('req/ip', '1.2.3.4', 60))).must_equal 3
      _(@store.read(shadow_key('req/ip', '1.2.3.4', 60))).must_equal 3

      _(@records.map(&:decision)).must_equal [:passed, :throttled, :throttled]
      _(@records.last.matched).must_equal 'req/ip'
      _(@records.last.match_type).must_equal :throttle
      _(@records.last.match_data[:count]).must_equal 3
    end
  end

  it 'fully evaluates shadow rules when the primary safelist returns early' do
    Rack::Attack.safelist('allow all') { |_req| true }
    Rack::Attack.shadow.blocklist('shadow block') { |req| req.ip == '1.2.3.4' }

    get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

    _(last_response.status).must_equal 200
    _(@records.size).must_equal 1
    _(@records.first.decision).must_equal :blocklisted
    _(@records.first.matched).must_equal 'shadow block'
  end

  it 'fully evaluates shadow rules when the primary blocklist returns early' do
    Rack::Attack.blocklist('primary block') { |_req| true }
    Rack::Attack.shadow.safelist('shadow safe') { |_req| true }

    get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

    # Response is decided by the primary configuration alone.
    _(last_response.status).must_equal 403
    _(@records.first.decision).must_equal :safelisted
  end

  it 'keeps env annotations from both configurations isolated' do
    Rack::Attack.blocklist('primary block') { |req| req.ip == '1.2.3.4' }
    Rack::Attack.shadow.throttle('shadow/ip', limit: 0, period: 60) { |req| req.ip }

    get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

    _(last_response.status).must_equal 403
    # Primary annotations are untouched by the shadow evaluation.
    _(last_request.env['rack.attack.matched']).must_equal 'primary block'
    _(last_request.env['rack.attack.match_type']).must_equal :blocklist
    _(last_request.env['rack.attack.throttle_data']).must_be_nil
    # Shadow annotations live only in the decision record.
    _(@records.first.decision).must_equal :throttled
    _(@records.first.matched).must_equal 'shadow/ip'
    _(@records.first.match_data[:count]).must_equal 1
  end

  it 'records unknown instead of passing when the shadow store fails' do
    broken_store = Object.new
    def broken_store.read(*); end

    def broken_store.write(*); end

    def broken_store.delete(*); end

    def broken_store.increment(*)
      raise 'store is down'
    end

    Rack::Attack.shadow.cache = Rack::Attack::Cache.new(store: broken_store)
    Rack::Attack.shadow.throttle('shadow/ip', limit: 1, period: 60) { |req| req.ip }

    get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

    _(last_response.status).must_equal 200
    _(@records.first.decision).must_equal :unknown
    _(@records.first.error).wont_be_nil
  end

  it 'does not affect the response when the shadow recorder fails' do
    Rack::Attack.shadow.recorder = ->(_record) { raise 'recorder is down' }

    _out, err = capture_io do
      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'
    end

    _(last_response.status).must_equal 200
    _(err).must_match(/Shadow recorder failed/)
  end

  it 'never lets shadow rules read an empty rack.input' do
    Rack::Attack.safelist('primary reads body') do |req|
      req.body.read
      false
    end
    Rack::Attack.shadow.blocklist('shadow body match') do |req|
      req.body.read.include?('attack')
    end

    post '/', 'attack=1', 'CONTENT_TYPE' => 'application/x-www-form-urlencoded'

    _(last_response.status).must_equal 200
    _(@records.first.decision).must_equal :blocklisted
    _(@records.first.matched).must_equal 'shadow body match'
  end

  it 'evaluates a request against a single rule version even when hot-swapped mid-request' do
    Rack::Attack.shadow.throttle('old rule', limit: 5, period: 60) { |req| req.ip }
    old_version = Rack::Attack.shadow.version

    Rack::Attack.blocklist('hot swapper') do |req|
      if req.ip == '1.2.3.4'
        Rack::Attack.shadow.clear_configuration
        Rack::Attack.shadow.blocklist('new rule') { |_r| true }
        Rack::Attack.shadow.version = 99
      end
      false
    end

    get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

    _(@records.first.version).must_equal old_version
    _(@records.first.decision).must_equal :passed
    _(@records.first.matched).must_be_nil
  end

  it 'does not instrument shadow matches as primary matches' do
    events = []
    subscriber = ActiveSupport::Notifications.subscribe(/rack_attack/) do |*args|
      events << args.last
    end

    Rack::Attack.shadow.blocklist('shadow block') { |_req| true }

    begin
      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

      _(last_response.status).must_equal 200
      _(events).must_be_empty
      _(@records.first.decision).must_equal :blocklisted
    ensure
      ActiveSupport::Notifications.unsubscribe(subscriber)
    end
  end
end
