require "logstash/jsendnsca-2.0.1.jar"
require "logstash/commons-lang-2.4.jar"
require "logstash/outputs/base"
require "logstash/namespace"
java_import com.googlecode.jsendnsca.encryption.Encryption

# The nagios_jsendnsca output is used for sending passive check results to Nagios
# through the NSCA protocol.
#
# This is useful if your Nagios server is not the same as the source host from
# where you want to send logs or alerts. If you only have one server, this
# output is probably overkill # for you, take a look at the 'nagios' output
# instead.
#
# Here is a sample config using the nagios_jsendnsca output:
#     output {
#       nagios_jsendnsca {
#         # specify the hostname or ip of your nagios server
#         host => "nagios.example.com"
#
#         # specify the port to connect to
#         port => 5667
#       }
#     }

class LogStash::Outputs::NagiosJSendNsca < LogStash::Outputs::Base

  config_name "nagios_jsendnsca"
  plugin_status "experimental"

  # The status to send to nagios. Should be 0 = OK, 1 = WARNING, 2 = CRITICAL, 3 = UNKNOWN
  config :nagios_status, :validate => :string, :required => true

  # The nagios host or IP to send logs to. It should have a NSCA daemon running.
  config :host, :validate => :string, :default => "localhost"

  # The port where the NSCA daemon on the nagios host listens.
  config :port, :validate => :number, :default => 5667

  # The nagios 'host' you want to submit a passive check result to. This
  # parameter accepts interpolation, e.g. you can use @source_host or other
  # logstash internal variables.
  config :nagios_host, :validate => :string, :default => "%{@source_host}"

  # The nagios 'service' you want to submit a passive check result to. This
  # parameter accepts interpolation, e.g. you can use @source_host or other
  # logstash internal variables.
  config :nagios_service, :validate => :string, :default => "LOGSTASH"

  public
  def register
    #nothing for now
  end

  public
  def receive(event)
    # exit if type or tags don't match
    return unless output?(event)

    # catch logstash shutdown
    if event == LogStash::SHUTDOWN
      finished
      return
    end

    # interpolate params
    nagios_host = event.sprintf(@nagios_host)
    nagios_service = event.sprintf(@nagios_service)

    # escape basic things in the log message
    # TODO: find a way to escape the message correctly
    msg = event.to_s
    msg.gsub!("\n", "<br/>")
    msg.gsub!("'", "&#146;")

    status = event.sprintf(@nagios_status)
    if status.to_i.to_s != status # Check it round-trips to int correctly
      msg = "status '#{status}' is not numeric"
      status = 2
    else
      status = status.to_i
      if status > 3 || status < 0
         msg "status must be > 0 and <= 3, not #{status}"
         status = 2
      end
    end

    # build the command
    # syntax: echo '<server>!<nagios_service>!<status>!<text>'  | \
    #           /usr/sbin/send_nsca -H <nagios_host> -d '!' -c <nsca_config>"
    cmd = %(echo '#{nagios_host}~#{nagios_service}~#{status}~#{msg}' |)
    cmd << %( #{@send_nsca_bin} -H #{@host} -p #{@port} -d '~')
    cmd << %( -c #{@send_nsca_config}) if @send_nsca_config
    cmd << %( 2>/tmp/test >/tmp/test)
    @logger.debug("Running send_nsca command", "nagios_nsca_command" => cmd)

    begin
      settings = Java::ComGooglecodeJsendnscaBuilders::NagiosSettingsBuilder.new()
            .withNagiosHost(@host)
            .withPort(@port)
            .withEncryption(Encryption::XOR)
            .create();
        
      payload = Java::ComGooglecodeJsendnscaBuilders::MessagePayloadBuilder.new()
            .withHostname(nagios_host)
            .withLevel(com.googlecode.jsendnsca.Level::CRITICAL)
            .withServiceName(nagios_service)
            .withMessage(msg)
            .create();

      sender = Java::ComGooglecodeJsendnsca::NagiosPassiveCheckSender.new(settings);

      sender.send(payload);
    rescue => e
      @logger.warn("Skipping nagios_jsendnsca output; error calling snder.send",
                   "error" => $!, "nagios_nsca_command" => cmd,
                   "missed_event" => event)
    end
  end # def receive
end # class LogStash::Outputs::NagiosJSendNsca
