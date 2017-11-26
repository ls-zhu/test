# Simple example to demonstrate object API for CWM

#require_relative "example_helper"
require './src/lib/TargetData.rb'
require './src/lib/dialogs/UI_dialogs.rb'
require "cwm/widget"
require "ui/service_status"
require "yast"

Yast.import "CWM"
Yast.import "CWMTab"
Yast.import "TablePopup"
Yast.import "CWMServiceStart"
Yast.import "Popup"
Yast.import "Wizard"
Yast.import "CWMFirewallInterfaces"
Yast.import "Service"
Yast.import "CWMServiceStart"
Yast.import "UI"


module Yast
  class ExampleDialog
    include Yast::I18n
    include Yast::UIShortcuts
    include Yast::Logger
    def run
      textdomain "example"
      global_tab = GlobalTab.new
      targets_tab = TargetsTab.new
      service_tab = ServiceTab.new
      tabs = ::CWM::Tabs.new(service_tab,global_tab,targets_tab)
      contents = VBox(tabs,VStretch())
      Yast::Wizard.CreateDialog
      ret = CWM.show(contents, caption: _("Yast iSCSI Targets"),next_button: _("Finish"))
      Yast::Wizard.CloseDialog
      p "in ExampleDialog, we got a return value which is ", ret
      if ret == :next
        status = $discovery_auth.fetch_status()
        userid = $discovery_auth.fetch_userid()
        password = $discovery_auth.fetch_password()
        mutual_userid = $discovery_auth.fetch_mutual_userid()
        mutual_password = $discovery_auth.fetch_mutual_password()
        puts status
        puts userid
        puts password
        puts mutual_userid
        puts mutual_password
        cmd = 'targetcli'
        p1 = "iscsi/ set discovery_auth userid = " + userid + " password = " + password + \
               " mutual_userid = " + mutual_userid + " mutual_password = " + mutual_password
        if status == true
          puts "It is true"
          p1 += " enable = 1"
        else
          puts "It is False"
          p1 += " enable = 0"
        end
        p p1
        begin
          Cheetah.run(cmd, p1)
        rescue Cheetah::ExecutionFailed => e
          Yast::Popup.Error(e.stderr) unless e.stderr.nil?
        end
        #TODO: Add code to check whether users provide the same username and password for incomfing and outgoing auth,
        #that will not work
      end
    end
  end
end

$target_data = TargetData.new
#$back_stores = Backstores.new
#back_stores.analyze
$discovery_auth = DiscoveryAuth.new
#$target_data.print
Yast::ExampleDialog.new.run
