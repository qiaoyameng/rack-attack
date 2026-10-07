# frozen_string_literal: true

require_relative "../spec_helper"
require "timecop"
require "timeout"

# An app whose responses are held back until the test releases them,
# allowing several requests to be in flight at the same time.
class LatchApp
  class Gate
    def initialize
      @queue = Queue.new
    end

    def wait
      @queue.pop
    end

    def release(status, chunks = ["chunk"])
      @queue << [status, chunks]
    end
  end

  def initialize
    @entered = Queue.new
  end

  def call(_env)
    gate = Gate.new
    @entered << gate
    status, chunks = gate.wait
    [status, { "content-type" => "text/plain" }, chunks]
  end

  def wait_for_gate
    @entered.pop
  end
end

# A body that records when it is actually streamed.
class RecordingBody
  attr_reader :read_count, :closed

  def initialize(chunks)
    @chunks = chunks
    @read_count = 0
    @closed = false
  end

  def each(&block)
    @read_count += 1
    @chunks.each(&block)
  end

  def close
    @closed = true
  end
end

# A body that streams one chunk and then blows up late.
class ExplodingBody
  def each
    yield "first"
    raise "boom"
  end

  def close; end
end

describe "throttle with count_on: :response" do
  let(:notifications) { [] }

  before do
    Rack::Attack.cache.store = ActiveSupport::Cache::MemoryStore.new
  end

  def env_for(ip = "1.2.3.4")
    Rack::MockRequest.env_for("/", "REMOTE_ADDR" => ip)
  end

  def consume_response(response)
    status, _headers, body = response
    chunks = []
    body.each { |chunk| chunks << chunk }
    body.close if body.respond_to?(:close)
    [status, chunks]
  end

  def cache_count(name = "logins", ip = "1.2.3.4", window = Time.now.to_i / 60)
    Rack::Attack.cache.store.read("rack::attack:#{window}:#{name}:#{ip}")
  end

  def subscribe_throttle_notifications
    ActiveSupport::Notifications.subscribe("throttle.rack_attack") do |*_args|
      notifications << true
    end
  end

  def status_app
    lambda do |env|
      status = env["HTTP_X_STATUS"] ? env["HTTP_X_STATUS"].to_i : 401
      [status, { "content-type" => "text/plain" }, ["app body"]]
    end
  end

  def throttle_logins(options = {})
    Rack::Attack.throttle("logins", {
      limit: 2,
      period: 60,
      count_on: :response,
      classify_response: ->(_req, status, _headers) { status == 401 }
    }.merge(options)) { |req| req.ip }
  end

  it "counts only responses the classifier marks as countable" do
    throttle_logins
    subscribe_throttle_notifications
    mw = Rack::Attack.new(status_app)

    env = env_for
    env["HTTP_X_STATUS"] = "200"
    status, chunks = consume_response(mw.call(env))
    _(status).must_equal 200
    _(chunks).must_equal ["app body"]
    _(cache_count).must_be_nil

    status, = consume_response(mw.call(env_for))
    _(status).must_equal 401
    _(cache_count).must_equal 1

    status, = consume_response(mw.call(env_for))
    _(status).must_equal 401
    _(cache_count).must_equal 2

    # quota is now exhausted by completed failures; the classifier never
    # runs for blocked requests and the count does not move
    status, chunks = consume_response(mw.call(env_for))
    _(status).must_equal 429
    _(chunks).must_equal ["Retry later\n"]
    _(cache_count).must_equal 2
    _(notifications.size).must_equal 1

    # a different IP still has its own quota
    status, = consume_response(mw.call(env_for("5.6.7.8")))
    _(status).must_equal 401
    _(cache_count("logins", "5.6.7.8")).must_equal 1
    _(notifications.size).must_equal 1
  end

  it "annotates the request with the peeked count" do
    throttle_logins
    mw = Rack::Attack.new(status_app)

    env = env_for
    consume_response(mw.call(env))
    data = env["rack.attack.throttle_data"]["logins"]
    _(data[:count]).must_equal 0
    _(data[:limit]).must_equal 2
    _(data[:period]).must_equal 60
    _(data[:discriminator]).must_equal "1.2.3.4"

    blocked_env = env_for
    consume_response(mw.call(env_for))
    consume_response(mw.call(blocked_env))
    _(blocked_env["rack.attack.matched"]).must_equal "logins"
    _(blocked_env["rack.attack.match_type"]).must_equal :throttle
    _(blocked_env["rack.attack.match_data"][:count]).must_equal 2
  end

  it "requires a classifier and valid option values" do
    error = assert_raises(ArgumentError) do
      Rack::Attack.throttle("x", limit: 1, period: 60, count_on: :response) { |req| req.ip }
    end
    _(error.message).must_match(/classify_response/)

    error = assert_raises(ArgumentError) do
      Rack::Attack.throttle("x", limit: 1, period: 60, count_on: :bogus) { |req| req.ip }
    end
    _(error.message).must_match(/count_on/)

    error = assert_raises(ArgumentError) do
      Rack::Attack.throttle("x", limit: 1, period: 60, count_on: :response, count_window: :bogus,
                                 classify_response: ->(_req, _status, _headers) { true }) { |req| req.ip }
    end
    _(error.message).must_match(/count_window/)
  end

  it "runs the classifier exactly once per request" do
    calls = 0
    classifier = lambda do |_req, _status, _headers|
      calls += 1
      true
    end
    throttle_logins(classify_response: classifier)
    mw = Rack::Attack.new(status_app)

    consume_response(mw.call(env_for))

    _(calls).must_equal 1
    _(cache_count).must_equal 1
  end

  it "streams the body through unchanged and never reads it for classification" do
    throttle_logins
    body = RecordingBody.new(%w[one two three])
    mw = Rack::Attack.new(->(_env) { [401, { "content-type" => "text/plain" }, body] })

    _status, _headers, response_body = *mw.call(env_for)

    # the app has returned, but nothing has been read or counted yet
    _(body.read_count).must_equal 0
    _(cache_count).must_be_nil

    chunks = []
    response_body.each { |chunk| chunks << chunk }
    _(chunks).must_equal %w[one two three]
    _(cache_count).must_equal 1

    response_body.close
    _(body.closed).must_equal true
    _(cache_count).must_equal 1
  end

  it "classifies app errors with on_app_error" do
    throttle_logins(on_app_error: true)
    mw = Rack::Attack.new(->(_env) { raise "app exploded" })

    assert_raises(RuntimeError) { mw.call(env_for) }
    _(cache_count).must_equal 1
  end

  it "does not count app errors by default" do
    throttle_logins
    mw = Rack::Attack.new(->(_env) { raise "app exploded" })

    assert_raises(RuntimeError) { mw.call(env_for) }
    _(cache_count).must_be_nil
  end

  it "classifies late body errors with on_body_error" do
    throttle_logins(on_body_error: ->(_req, error) { error.message == "boom" })
    mw = Rack::Attack.new(->(_env) { [200, { "content-type" => "text/plain" }, ExplodingBody.new] })

    _status, _headers, body = *mw.call(env_for)
    chunks = []
    error = assert_raises(RuntimeError) do
      body.each { |chunk| chunks << chunk }
    end
    _(error.message).must_equal "boom"
    _(chunks).must_equal ["first"]
    _(cache_count).must_equal 1

    body.close
    _(cache_count).must_equal 1
  end

  it "does not count late body errors by default" do
    throttle_logins
    mw = Rack::Attack.new(->(_env) { [200, { "content-type" => "text/plain" }, ExplodingBody.new] })

    _status, _headers, body = *mw.call(env_for)
    assert_raises(RuntimeError) { body.each {} }
    _(cache_count).must_be_nil
  end

  it "classifies classifier errors with on_classifier_error" do
    throttle_logins(
      classify_response: ->(_req, _status, _headers) { raise "classifier exploded" },
      on_classifier_error: true
    )
    mw = Rack::Attack.new(status_app)

    status, chunks = consume_response(mw.call(env_for))
    _(status).must_equal 401
    _(chunks).must_equal ["app body"]
    _(cache_count).must_equal 1
  end

  it "does not count classifier errors by default" do
    throttle_logins(classify_response: ->(_req, _status, _headers) { raise "classifier exploded" })
    mw = Rack::Attack.new(status_app)

    status, = consume_response(mw.call(env_for))
    _(status).must_equal 401
    _(cache_count).must_be_nil
  end

  it "attributes the count to the request-start window with count_window: :start" do
    throttle_logins(limit: 1, count_window: :start)
    mw = Rack::Attack.new(status_app)

    body = nil
    Timecop.freeze(Time.at(600)) do
      _status, _headers, body = *mw.call(env_for)
    end

    Timecop.freeze(Time.at(660)) do
      body.each {}
      body.close

      _(cache_count("logins", "1.2.3.4", 10)).must_equal 1
      _(cache_count("logins", "1.2.3.4", 11)).must_be_nil

      # the completed failure belongs to the previous window, so this
      # window still has quota
      status, = consume_response(mw.call(env_for))
      _(status).must_equal 401
      _(cache_count("logins", "1.2.3.4", 11)).must_equal 1
    end
  end

  it "attributes the count to the completion window with count_window: :finish" do
    throttle_logins(limit: 1, count_window: :finish)
    mw = Rack::Attack.new(status_app)

    body = nil
    Timecop.freeze(Time.at(600)) do
      _status, _headers, body = *mw.call(env_for)
    end

    Timecop.freeze(Time.at(660)) do
      body.each {}
      body.close

      _(cache_count("logins", "1.2.3.4", 10)).must_be_nil
      _(cache_count("logins", "1.2.3.4", 11)).must_equal 1

      # the count landed in this window, so the quota is already spent
      status, = consume_response(mw.call(env_for))
      _(status).must_equal 429
    end
  end

  it "checks completed counts at entry and settles in-flight requests as responses complete" do
    throttle_logins(limit: 1)
    subscribe_throttle_notifications

    app = LatchApp.new
    mw = Rack::Attack.new(app)

    Timeout.timeout(10) do
      Timecop.freeze(Time.at(6000)) do
        results = Queue.new
        threads = Array.new(2) { Thread.new { results << consume_response(mw.call(env_for)) } }

        gate1 = app.wait_for_gate
        gate2 = app.wait_for_gate

        # both requests entered while the completed failure count was still
        # zero, so both were allowed in
        gate1.release(401, ["Unauthorized"])
        status, chunks = results.pop
        _(status).must_equal 401
        _(chunks).must_equal ["Unauthorized"]
        _(cache_count).must_equal 1
        _(notifications.size).must_equal 0

        # the second request was already past the entry check when the first
        # one settled; counting after completion cannot strictly limit
        # requests that entered concurrently
        gate2.release(401, ["Unauthorized"])
        status, = results.pop
        _(status).must_equal 401
        _(cache_count).must_equal 2
        _(notifications.size).must_equal 0

        threads.each(&:join)

        # the next request sees both completed failures and is blocked
        status, = consume_response(mw.call(env_for))
        _(status).must_equal 429
        _(cache_count).must_equal 2
        _(notifications.size).must_equal 1
      end
    end
  end

  describe "through the full middleware stack" do
    def app
      Rack::Builder.new do
        use Rack::Lint
        use Rack::Attack
        run lambda { |_env| [401, { "content-type" => "text/plain" }, ["Hello World"]] }
      end.to_app
    end

    it "passes Rack::Lint while counting classified responses" do
      throttle_logins

      get "/", {}, "REMOTE_ADDR" => "1.2.3.4"
      _(last_response.status).must_equal 401
      _(last_response.body).must_equal "Hello World"
      _(cache_count).must_equal 1

      get "/", {}, "REMOTE_ADDR" => "1.2.3.4"
      _(cache_count).must_equal 2

      get "/", {}, "REMOTE_ADDR" => "1.2.3.4"
      _(last_response.status).must_equal 429
      _(cache_count).must_equal 2
    end
  end
end
