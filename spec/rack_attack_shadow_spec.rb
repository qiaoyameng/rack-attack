# frozen_string_literal: true

require_relative 'spec_helper'
require 'active_support/cache'

describe 'Rack::Attack shadow configuration' do
  before do
    @records = []
    Rack::Attack.shadow_recorder = ->(record) { @records << record }
    Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new
    Rack::Attack.shadow_cache = ActiveSupport::Cache::MemoryStore.new
  end

  after do
    Rack::Attack.shadow_recorder = nil
    Rack::Attack.clear_shadow_configuration
    Rack::Attack.shadow_cache = ActiveSupport::Cache::MemoryStore.new
  end

  def body_app
    Rack::Builder.new do
      use Rack::Attack
      run ->(env) { [200, { 'content-type' => 'text/plain' }, ["downstream:#{env['rack.input'].read}"]] }
    end.to_app
  end

  def post_body(app, body, headers = {})
    input = StringIO.new(body)
    status, _, response = app.call(
      'REQUEST_METHOD' => 'POST',
      'PATH_INFO' => '/',
      'REMOTE_ADDR' => headers.delete('REMOTE_ADDR') || '1.2.3.4',
      'rack.input' => input,
      'rack.errors' => StringIO.new,
      'HTTP_USER_AGENT' => headers.delete('HTTP_USER_AGENT')
    )
    result = [status, response.join, input]
    input.rewind
    result
  end

  it "does not change the response even when the shadow would block" do
    Rack::Attack.shadow { blocklist('bad') { |req| req.ip == '1.2.3.4' } }

    get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

    _(last_response.status).must_equal 200
    _(@records.size).must_equal 1
    _(@records.first[:verdict]).must_equal :block
    _(@records.first[:reason]).must_equal 'blocklist'
  end

  it "fully evaluates shadow rules even when production safelist returns early" do
    Rack::Attack.safelist('trusted') { |req| req.user_agent == 'Trusted' }
    Rack::Attack.shadow { blocklist('bad ua') { |req| req.user_agent == 'Trusted' } }

    get '/', {}, 'HTTP_USER_AGENT' => 'Trusted'

    _(last_response.status).must_equal 200
    record = @records.first
    _(record[:verdict]).must_equal :block
    _(record[:reason]).must_equal 'blocklist'
    _(record[:matched]).must_equal 'bad ua'
  end

  it "fully evaluates shadow rules even when production blocklist returns early" do
    Rack::Attack.blocklist('prod bad') { |req| req.ip == '9.9.9.9' }
    Rack::Attack.shadow { safelist('shadow good') { |req| req.ip == '9.9.9.9' } }

    get '/', {}, 'REMOTE_ADDR' => '9.9.9.9'

    _(last_response.status).must_equal 403
    record = @records.first
    _(record[:verdict]).must_equal :allow
    _(record[:reason]).must_equal 'safelist'
    _(record[:matched]).must_equal 'shadow good'
  end

  it "keeps shadow annotations separate and never overwrites production env" do
    Rack::Attack.blocklist('prod bad') { |req| req.ip == '9.9.9.9' }
    Rack::Attack.shadow { blocklist('shadow bad') { |req| req.ip == '9.9.9.9' } }

    get '/', {}, 'REMOTE_ADDR' => '9.9.9.9'

    env = last_request.env
    _(env['rack.attack.matched']).must_equal 'prod bad'
    _(env['rack.attack.match_type']).must_equal :blocklist
    _(env['rack.attack.shadow.matched']).must_be_nil
    _(env['rack.attack.shadow.match_type']).must_be_nil

    record = @records.first
    _(record[:matched]).must_equal 'shadow bad'
    _(record[:match_type]).must_equal :blocklist
  end

  it "does not let shadow instrumentation annotate the production request" do
    Rack::Attack.shadow { track('all') { |_req| true } }

    get '/'

    _(last_request.env['rack.attack.matched']).must_be_nil
    _(last_request.env['rack.attack.match_type']).must_be_nil
    _(@records.first[:verdict]).must_equal :allow
  end

  it "records the rule/config versions and the match reason" do
    Rack::Attack.shadow { blocklist('bad') { |req| req.ip == '1.2.3.4' } }
    config = Rack::Attack.shadow_configuration

    get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

    record = @records.first
    _(record[:rule_version]).must_equal config.version
    _(record[:configuration_version]).must_equal config.version
    _(record[:reason]).must_equal 'blocklist'
    _(record[:request][:ip]).must_equal '1.2.3.4'
    _(record[:request][:path]).must_equal '/'
  end

  it "uses a separate counting namespace from production counters" do
    Rack::Attack.throttle('prod ip', limit: 100, period: 60) { |req| req.ip }
    Rack::Attack.shadow { throttle('shadow ip', limit: 1, period: 60) { |req| req.ip } }

    get '/', {}, 'REMOTE_ADDR' => '5.5.5.5'
    get '/', {}, 'REMOTE_ADDR' => '5.5.5.5'

    _(last_response.status).must_equal 200
    _(@records.last[:verdict]).must_equal :throttle

    formal_data = Rack::Attack.cache.store
    shadow_data = Rack::Attack.shadow_cache.store
    period = Time.now.to_i / 60
    _(formal_data.read("rack::attack:#{period}:prod ip:5.5.5.5")).must_equal 2
    _(shadow_data.read("rack::attack-shadow:#{period}:shadow ip:5.5.5.5")).must_equal 2
    _(shadow_data.read("rack::attack:#{period}:prod ip:5.5.5.5")).must_be_nil
  end

  it "collects the request body once and leaves rack.input full for the downstream app" do
    Rack::Attack.shadow do
      blocklist('posted secret') { |req| req.body.read.include?('shadow-trigger') }
    end

    status, body, input = post_body(body_app, 'payload=shadow-trigger')

    _(status).must_equal 200
    _(body).must_equal 'downstream:payload=shadow-trigger'
    _(@records.first[:verdict]).must_equal :block
    _(input.read).must_equal 'payload=shadow-trigger'
  end

  it "leaves rack.input intact when shadow rules read a non-triggering body" do
    Rack::Attack.shadow do
      blocklist('posted secret') { |req| req.body.read.include?('nope') }
    end

    status, body, _input = post_body(body_app, 'payload=fine')

    _(status).must_equal 200
    _(body).must_equal 'downstream:payload=fine'
    _(@records.first[:verdict]).must_equal :allow
    _(@records.first[:reason]).must_equal 'no_match'
  end

  it "records :unknown instead of silently allowing when the shadow store fails" do
    Rack::Attack.shadow { throttle('shadow ip', limit: 1, period: 60) { |req| req.ip } }
    Rack::Attack.shadow_cache = nil

    broken_store = Object.new
    def broken_store.increment(*)
      raise RuntimeError, "boom"
    end

    Rack::Attack.shadow_cache = Rack::Attack::Cache.new(store: broken_store)
    Rack::Attack.shadow_cache.prefix = 'rack::attack-shadow'

    get '/', {}, 'REMOTE_ADDR' => '3.3.3.3'

    _(last_response.status).must_equal 200
    record = @records.first
    _(record[:verdict]).must_equal :unknown
    _(record[:reason]).must_equal 'error'
    _(record[:error]).must_include 'boom'
  end

  it "records :unknown when the recorder itself raises and never affects the response" do
    Rack::Attack.shadow { blocklist('bad') { |req| req.ip == '1.2.3.4' } }

    fallback = []
    fake_notifier = Object.new
    fake_notifier.define_singleton_method(:instrument) do |event, payload|
      fallback << [event, payload]
    end

    previous_notifier = Rack::Attack.notifier
    begin
      Rack::Attack.notifier = fake_notifier
      Rack::Attack.shadow_recorder = ->(_record) { raise 'recorder down' }
      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'
    ensure
      Rack::Attack.notifier = previous_notifier
    end

    _(last_response.status).must_equal 200
    event, payload = fallback.last
    _(event).must_equal 'shadow.rack_attack'
    _(payload[:verdict]).must_equal :unknown
    _(payload[:reason]).must_equal 'recorder_error'
  end

  it "binds one request to a single shadow version across a hot configuration swap" do
    Rack::Attack.shadow do
      blocklist('v1 swap rule') do |_req|
        # Swap the live configuration in the middle of this request's shadow run.
        Rack::Attack.shadow { blocklist('v2 rule') { |_req| false } }
        false
      end
    end
    v1 = Rack::Attack.shadow_configuration

    get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

    record = @records.first
    _(record[:rule_version]).must_equal v1.version
    _(record[:configuration_version]).must_equal v1.version
    _(record[:reason]).must_equal 'no_match'
    _(Rack::Attack.shadow_configuration.version).wont_equal v1.version
  end

  it "emits nothing when no shadow configuration is present" do
    get '/'

    _(@records).must_be :empty?
    _(last_response.status).must_equal 200
  end

  it "produces three independent views: production counts, shadow counts and response" do
    Rack::Attack.throttle('prod ip', limit: 2, period: 60) { |req| req.ip }
    Rack::Attack.shadow { throttle('shadow ip', limit: 1, period: 60) { |req| req.ip } }

    statuses = Array.new(3) do
      get '/', {}, 'REMOTE_ADDR' => '7.7.7.7'
      last_response.status
    end

    period = Time.now.to_i / 60
    formal_count = Rack::Attack.cache.store.read("rack::attack:#{period}:prod ip:7.7.7.7")
    shadow_count = Rack::Attack.shadow_cache.store.read("rack::attack-shadow:#{period}:shadow ip:7.7.7.7")

    _(statuses).must_equal [200, 200, 429]
    _(formal_count).must_equal 3
    _(shadow_count).must_equal 3
    _(@records.map { |r| r[:verdict] }).must_equal [:allow, :throttle, :throttle]
  end
end
