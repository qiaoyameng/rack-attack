# frozen_string_literal: true

require_relative 'spec_helper'
require_relative 'support/freeze_time_helper'

class FakeNotifier
  attr_reader :events

  def initialize
    @events = []
  end

  def instrument(name, _payload)
    @events << name
  end
end

describe 'Rack::Attack.throttle with count_on: :response' do
  before do
    @period = 60
    @limit = 2
    Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new

    @old_notifier = Rack::Attack.notifier
    @notifier = FakeNotifier.new
    Rack::Attack.notifier = @notifier
  end

  after do
    Rack::Attack.notifier = @old_notifier
  end

  def register_throttle(**options)
    defaults = {
      limit: @limit,
      period: @period,
      count_on: :response,
      classify_response: ->(_req, res) { res.status == 401 }
    }
    Rack::Attack.throttle('login failures', defaults.merge(options)) { |req| req.ip }
  end

  def failure_count(ip = '1.2.3.4')
    key = "rack::attack:#{Time.now.to_i / @period}:login failures:#{ip}"
    Rack::Attack.cache.store.read(key) || 0
  end

  def app
    Rack::Attack.new(lambda do |env|
      status = env['PATH_INFO'] == '/fail' ? 401 : 200
      [status, { 'content-type' => 'text/plain' }, ['app body']]
    end)
  end

  describe 'option validation' do
    it 'requires a callable classify_response' do
      error = assert_raises(ArgumentError) do
        Rack::Attack.throttle('x', limit: 1, period: 60, count_on: :response) { |req| req.ip }
      end
      _(error.message).must_match(/classify_response/)
    end

    it 'rejects unknown count_on values' do
      assert_raises(ArgumentError) do
        Rack::Attack.throttle('x', limit: 1, period: 60, count_on: :bogus) { |req| req.ip }
      end
    end

    it 'rejects unknown count_window values' do
      assert_raises(ArgumentError) do
        register_throttle(count_window: :bogus)
      end
    end

    it 'rejects unknown error classification values' do
      assert_raises(ArgumentError) { register_throttle(on_app_error: :bogus) }
      assert_raises(ArgumentError) { register_throttle(on_body_error: :bogus) }
      assert_raises(ArgumentError) { register_throttle(on_classifier_error: :bogus) }
    end
  end

  describe 'failure counting' do
    before { register_throttle }

    it 'does not count successful responses' do
      within_same_period do
        3.times { get '/', {}, 'REMOTE_ADDR' => '1.2.3.4' }

        _(last_response.status).must_equal 200
        _(failure_count).must_equal 0
      end
    end

    it 'counts failed responses and throttles once the limit is reached' do
      within_same_period do
        2.times do
          get '/fail', {}, 'REMOTE_ADDR' => '1.2.3.4'
          _(last_response.status).must_equal 401
        end
        _(failure_count).must_equal 2

        get '/fail', {}, 'REMOTE_ADDR' => '1.2.3.4'
        _(last_response.status).must_equal 429
        _(failure_count).must_equal 2

        get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'
        _(last_response.status).must_equal 429
      end
    end

    it 'tracks failures per discriminator' do
      within_same_period do
        2.times { get '/fail', {}, 'REMOTE_ADDR' => '1.2.3.4' }

        get '/', {}, 'REMOTE_ADDR' => '5.6.7.8'
        _(last_response.status).must_equal 200
        _(failure_count('5.6.7.8')).must_equal 0
      end
    end

    it 'annotates throttle data with the completed failure count' do
      within_same_period do
        get '/fail', {}, 'REMOTE_ADDR' => '1.2.3.4'
        get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

        data = last_request.env['rack.attack.throttle_data']['login failures']
        _(data[:count]).must_equal 1
        _(data[:limit]).must_equal @limit
        _(data[:period]).must_equal @period
        _(data[:discriminator]).must_equal '1.2.3.4'
      end
    end

    it 'notifies only for throttled requests' do
      within_same_period do
        2.times { get '/fail', {}, 'REMOTE_ADDR' => '1.2.3.4' }
        _(@notifier.events.count('throttle.rack_attack')).must_equal 0

        2.times { get '/', {}, 'REMOTE_ADDR' => '1.2.3.4' }
        _(@notifier.events.count('throttle.rack_attack')).must_equal 2
      end
    end
  end

  describe 'the response classifier' do
    it 'receives the request and a response snapshot without the body' do
      seen = nil
      register_throttle(classify_response: ->(req, res) {
        seen = [req, res]
        false
      })

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

      request, response = seen
      _(request.ip).must_equal '1.2.3.4'
      _(response.status).must_equal 200
      _(response.headers['content-type']).must_equal 'text/plain'
      _(response).wont_respond_to :body
    end

    it 'runs exactly once per completed response' do
      calls = 0
      register_throttle(classify_response: ->(_req, _res) {
        calls += 1
        false
      })

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'

      _(calls).must_equal 1
    end
  end

  describe 'body streaming' do
    it 'passes the body through untouched and never reads it for classification' do
      register_throttle

      chunks = ['Hello', ' ', 'World']
      read = false
      body = Object.new
      body.define_singleton_method(:each) do |&blk|
        read = true
        chunks.each(&blk)
      end

      streaming_app = Rack::Attack.new(->(_env) { [200, { 'content-type' => 'text/plain' }, body] })
      env = Rack::MockRequest.env_for('/', 'REMOTE_ADDR' => '1.2.3.4')

      status, _headers, response_body = streaming_app.call(env)
      _(status).must_equal 200
      _(read).must_equal false

      collected = []
      response_body.each { |chunk| collected << chunk }
      _(collected).must_equal chunks
    end
  end

  describe 'when the application raises' do
    def app
      Rack::Attack.new(->(_env) { raise 'boom' })
    end

    it 'does not count by default' do
      register_throttle

      assert_raises(RuntimeError) { get '/', {}, 'REMOTE_ADDR' => '1.2.3.4' }
      _(failure_count).must_equal 0
    end

    it 'counts when on_app_error is :count' do
      register_throttle(on_app_error: :count)

      assert_raises(RuntimeError) { get '/', {}, 'REMOTE_ADDR' => '1.2.3.4' }
      _(failure_count).must_equal 1
    end

    it 'defers to a callable on_app_error' do
      seen = nil
      register_throttle(on_app_error: ->(req, exception) {
        seen = [req, exception]
        true
      })

      assert_raises(RuntimeError) { get '/', {}, 'REMOTE_ADDR' => '1.2.3.4' }
      _(failure_count).must_equal 1
      _(seen[0].ip).must_equal '1.2.3.4'
      _(seen[1].message).must_equal 'boom'
    end
  end

  describe 'when the response body raises while streaming' do
    def erroring_body
      body = Object.new
      def body.each
        yield 'partial'
        raise IOError, 'socket gone'
      end
      body
    end

    def streaming_app
      body = erroring_body
      Rack::Attack.new(->(_env) { [200, { 'content-type' => 'text/plain' }, body] })
    end

    it 'does not count by default' do
      register_throttle

      _status, _headers, body = streaming_app.call(Rack::MockRequest.env_for('/', 'REMOTE_ADDR' => '1.2.3.4'))
      assert_raises(IOError) { body.each { |chunk| } }
      _(failure_count).must_equal 0
    end

    it 'counts when on_body_error is :count, independently of classify_response' do
      register_throttle(classify_response: ->(_req, _res) { false }, on_body_error: :count)

      _status, _headers, body = streaming_app.call(Rack::MockRequest.env_for('/', 'REMOTE_ADDR' => '1.2.3.4'))
      assert_raises(IOError) { body.each { |chunk| } }
      _(failure_count).must_equal 1
    end
  end

  describe 'when the classifier raises' do
    it 'does not count by default' do
      register_throttle(classify_response: ->(_req, _res) { raise 'classifier boom' })

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'
      _(last_response.status).must_equal 200
      _(failure_count).must_equal 0
    end

    it 'counts when on_classifier_error is :count' do
      register_throttle(
        classify_response: ->(_req, _res) { raise 'classifier boom' },
        on_classifier_error: :count
      )

      get '/', {}, 'REMOTE_ADDR' => '1.2.3.4'
      _(failure_count).must_equal 1
    end
  end

  describe 'count_window' do
    def unauthorized_app
      Rack::Attack.new(->(_env) { [401, { 'content-type' => 'text/plain' }, ['no']] })
    end

    def window_key(epoch, ip = '1.2.3.4')
      "rack::attack:#{epoch / @period}:login failures:#{ip}"
    end

    it 'attributes the count to the window at request start with :start' do
      register_throttle(count_window: :start)

      env = Rack::MockRequest.env_for('/', 'REMOTE_ADDR' => '1.2.3.4')
      Timecop.freeze(Time.at(50)) do
        _status, _headers, body = unauthorized_app.call(env)
        Timecop.travel(Time.at(70)) { body.each { |chunk| } }

        _(Rack::Attack.cache.store.read(window_key(50))).must_equal 1
        _(Rack::Attack.cache.store.read(window_key(70))).must_be_nil
      end
    end

    it 'attributes the count to the window at completion with :finish' do
      register_throttle(count_window: :finish)

      env = Rack::MockRequest.env_for('/', 'REMOTE_ADDR' => '1.2.3.4')
      Timecop.freeze(Time.at(50)) do
        _status, _headers, body = unauthorized_app.call(env)
        Timecop.travel(Time.at(70)) { body.each { |chunk| } }

        _(Rack::Attack.cache.store.read(window_key(50))).must_be_nil
        _(Rack::Attack.cache.store.read(window_key(70))).must_equal 1
      end
    end
  end

  describe 'concurrent in-flight requests' do
    it 'settles each response independently and reconciles quota, blocking and notifications' do
      register_throttle

      arrived = Queue.new
      release = Queue.new
      latch_app = lambda do |_env|
        arrived << true
        release.pop
      end
      latched_app = Rack::Attack.new(latch_app)

      make_request = lambda do
        env = Rack::MockRequest.env_for('/', 'REMOTE_ADDR' => '1.2.3.4')
        status, _headers, body = latched_app.call(env)
        body.each { |chunk| }
        body.close if body.respond_to?(:close)
        status
      end

      Timecop.freeze(Time.at(1000)) do
        done = Queue.new
        threads = Array.new(2) { Thread.new { done << make_request.call } }

        # Both requests entered the app concurrently; nothing has completed,
        # so no failures are counted and both were allowed through.
        2.times { arrived.pop }
        _(failure_count).must_equal 0

        release << [401, { 'content-type' => 'text/plain' }, ['no']]
        _(done.pop).must_equal 401
        _(failure_count).must_equal 1
        _(@notifier.events.count('throttle.rack_attack')).must_equal 0

        release << [401, { 'content-type' => 'text/plain' }, ['no']]
        _(done.pop).must_equal 401
        _(failure_count).must_equal 2
        _(@notifier.events.count('throttle.rack_attack')).must_equal 0

        # The quota is exhausted: further requests are throttled, notified,
        # and do not consume more quota themselves.
        2.times { _(make_request.call).must_equal 429 }
        _(failure_count).must_equal 2
        _(@notifier.events.count('throttle.rack_attack')).must_equal 2

        threads.each(&:join)
      end
    end
  end
end
