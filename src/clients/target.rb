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
    #require './src/clients/TargetData.rb'

    def initialize
       #TargetData.test
       #p TargetData.GetNetConfig
    end

    def run
      textdomain "example"

      global_tab = GlobalTab.new
      targets_tab = TargetsTab.new
      service_tab =ServiceTab.new

      tabs = ::CWM::Tabs.new(service_tab,global_tab,targets_tab)

      contents = VBox(tabs,VStretch())

      Yast::Wizard.CreateDialog
      CWM.show(contents, caption: _("Yast iSCSI Targets"),next_button: _("Finish"))
      Yast::Wizard.CloseDialog

     # log.info "Lucky number: #{lucky_number_tab.result}, true love: #{true_love_tab.result}"
    end
  end
end

$target_data = TargetData.new
$back_stores = Backstores.new
#back_stores.analyze
$target_data.print
Yast::ExampleDialog.new.run
