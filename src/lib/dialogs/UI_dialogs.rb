# Simple example to demonstrate object API for CWM

# require_relative "example_helper"
require './src/lib/helps/example_helper.rb'
require './src/lib/TargetData.rb'
require 'cwm/widget'
require 'ui/service_status'
require 'yast'
require 'cwm/table'
require 'cwm/dialog'
require 'yast2/execute'

Yast.import 'CWM'
Yast.import 'CWMTab'
Yast.import 'TablePopup'
Yast.import 'CWMServiceStart'
Yast.import 'Popup'
Yast.import 'Wizard'
Yast.import 'CWMFirewallInterfaces'
Yast.import 'SuSEFirewall'
Yast.import 'Service'
Yast.import 'CWMServiceStart'
Yast.import 'UI'
Yast.import 'TablePopup'

class NoDiscoveryAuth_widget < ::CWM::CheckBox
  def initialize
    textdomain 'example'
  end

  def label
    _('No Discovery Authentication')
  end

  # auto called from Yast
  def init
    self.value = true # TODO: read config
  end

  def store
    puts "IT IS #{value}!!!"
  end

  def handle
    puts 'Changed!'
  end

  def opt
    [:notify]
  end
end

# used to enable / disable 0.0.0.0 IP portal
class BindAllIP < ::CWM::CheckBox
  def initialize
    textdomain 'example'
  end

  def label
    _('Bind all IP addresses')
  end

  # auto called from Yast
  def init
    self.value = true # TODO: read config
  end

  def store
    puts "IT IS #{value}!!!"
  end

  def handle
    puts 'Changed!'
  end

  def opt
    [:notify]
  end
end

class UseLoginAuth < ::CWM::CheckBox
  def initialize
    textdomain 'example'
  end

  def label
    _('Use Login Authentication')
  end

  # auto called from Yast
  def init
    self.value = true # TODO: read config
  end

  def store
    puts "IT IS #{value}!!!"
  end

  def handle
    puts 'Changed!'
  end

  def opt
    [:notify]
  end
end

# Class used to check whether initiator side auth is enabled
class Auth_by_Initiators_widget < ::CWM::CheckBox
  def initialize
    textdomain 'example'
  end

  def label
    _("Authentication by initiators.\n")
  end

  # auto called from Yast
  def init
    self.value = true # TODO: read config
  end

  def store
    puts "IT IS #{value}!!!"
  end

  def handle
    puts 'Changed!'
  end

  def opt
    [:notify]
  end
end

class Auth_by_Targets_widget < ::CWM::CheckBox
  def initialize
    textdomain 'example'
  end

  def label
    _('Autnentication by Targets')
  end

  # auto called from Yast
  def init
    self.value = true # TODO: read config
  end

  def store
    puts "IT IS #{value}!!!"
  end

  def handle
    puts 'Changed!'
  end

  def opt
    [:notify]
  end
end

class UserName < CWM::InputField
  def initialize(str)
    @config = str
  end

  def label
    _('Username:')
  end

  def init
    self.value = @config
    printf("Username InputField init, got default value %s.\n", @config)
  end

  def store
    @config = value
    printf("Username Inputfield will store the value %s.\n", @config)
  end
end

class Password < CWM::InputField
  def initialize(str)
    @config = str
  end

  def label
    _('Password:')
  end

  def init
    self.value = @config
    printf("Password InputField init, got default value %s.\n", @config)
  end

  def store
    @config = value
    printf("Password Inputfield will store the value %s.\n", @config)
  end
end

class MutualUserName < CWM::InputField
  def initialize(str)
    @config = str
  end

  def label
    _('Mutual Username:')
  end

  def init
    self.value = @config
    printf("Mutual Username InputField init, got default value %s.\n", @config)
  end

  def store
    @config = value
    printf("Mutual Username Inputfield will store the value %s.\n", @config)
  end
end

class MutualPassword < CWM::InputField
  def initialize(str)
    @config = str
  end

  def label
    _('Mutual Password:')
  end

  def init
    self.value = @config
    printf("Mutual Password InputField init, got default value %s.\n", @config)
  end

  def store
    @config = value
    printf("Mutual Password Inputfield will store the value %s.\n", @config)
  end
end

module Yast
  class ServiceTab < ::CWM::Tab
    # @fire_wall_service = nil
    include Yast::I18n
    include Yast::UIShortcuts
    def initialize
      # Yast.import "SuSEFirewall"
      self.initial = true
      @service = Yast::SystemdService.find('targetcli')
      @service_status = ::UI::ServiceStatus.new(@service, reload_flag: true, reload_flag_label: :restart)
      # self.Read()
      # SuSEFirewall.Read()
    end

    def Read
      SuSEFirewall.Read()
    end

    def contents
      HBox(
        ::CWM::WrapperWidget.new(
          CWMFirewallInterfaces.CreateOpenFirewallWidget('services' => ['service:target']),
          id: 'firewall'
        ),
        @service_status.widget
      )
    end

    def label
      _('Service')
    end
  end
end
class GlobalTab < ::CWM::Tab
  def initialize
    self.initial = true
  end

  def contents
    VBox(
      # HStretch(),
      VStretch(),
      NoDiscoveryAuth_widget.new,
      Auth_by_Targets_widget.new,
      HBox(
        UserName.new('test username'),
        Password.new('test password')
      ),
      Auth_by_Initiators_widget.new,
      HBox(
        MutualUserName.new('test mutual username'),
        MutualPassword.new('test mutual password')
      )
    )
  end

  def label
    _('Global')
  end
end

class TargetsTab < ::CWM::Tab
  def initialize
    @target_table_widget = TargetsTableWidget.new
    # puts "Initialized a TargetsTab class."
    self.initial = false
  end

  def contents
    VBox(
      HStretch(),
      VStretch(),
      @target_table_widget
    )
  end

  def label
    _('Targets')
  end
end

class TargetNameInput < CWM::InputField
  def initialize(str)
    printf("TargetName got default value %s.\n", str)
    @config = str.downcase
    @iscsi_name_length_max = 233
  end

  def label
    _('Target')
  end

  def validate
    puts 'Validate in TargetNameInput is called.'
    if value.empty?
      Yast::Popup.Error(_('Target name cannot be empty.'))
      return false
    elsif value.bytesize > @iscsi_name_length_max
      Yast::Popup.Error(_('Target name cannot be longger than 223 bytes.'))
      return false
    end
    true
  end

  def init
    self.value = @config.downcase
  end

  def store
    @config = value.downcase
  end

  def get_value
    value.downcase
  end
end

class TargetIdentifierInput < CWM::InputField
  def initialize(str)
    @config = str.downcase
  end

  def label
    _('Identifier')
  end

  def validate
    self.value = @config.downcase
    # printf("In TargetIndentifierInput Validate, self.value is %s.\n", value)
    true
  end

  def init
    self.value = @config.downcase
    # printf("Target Identifier InputField init, got default value %s.\n",@config)
  end

  def store
    @config = value.downcase
    # printf("Target Identifier Inputfield will store the value %s.\n", @config)
  end

  def get_value
    value.downcase
  end
end

class PortalGroupInput < CWM::IntField
  def initialize(num)
    @config = num.to_i
    # p num.class
    # printf("@config is %d.\n", @config)
  end

  def label
    _('Portal Group')
  end

  def init
    self.value = @config
    # printf("Target Portal Group InputField init, got default value %s.\n",@config)
  end

  def store
    @config = value
    # printf("Target Portal Group will store the value %s.\n", @config)
  end

  def minimum
    0
  end
end

class TargetPortNumberInput < CWM::IntField
  def initialize(int)
    @config = int
  end

  def label
    _('Port Number')
  end

  def init
    self.value = @config
    # printf("Target port number InputField init, got default value %s.\n",@config)
  end

  def store
    @config = value
    # printf("Target port number will store the value %s.\n", @config)
  end

  def minimum
    0
  end
end

class IpSelectionComboBox < CWM::ComboBox
  def initialize
    @addrs = nil
    # @config = myconfig
  end

  def label
    _('IP Address:')
  end

  def init
    # self.value = @config.value
  end

  def store
    # @config.value = value
    # puts self.value
    # puts get_addr
  end

  def GetNetConfig
    ip_list = []
    re_ipv4 = Regexp.new(/[\d+\.]+\//)
    re_ipv6 = Regexp.new(/[\w+\:]+\//)
    ret = Yast::Execute.locally('ip', 'a', stdout: :capture)
    ip = ret.split("\n")
    ip.each do |line|
      line = line.strip
      if line.include?('inet') && !line.include?('deprecated') # don't show deprecated IPs
        if line.include?('inet6')
          ip_str = re_ipv6.match(line).to_s.delete!('/')
          if ip_str.start_with?('::1')
            next
          elsif ip_str.start_with?('fe80:')
            next
          else
            # p ip_str
            ip_list.push(ip_str)
          end
        else
          # delete "/", and drop 127.x.x.x locall address
          ip_str = re_ipv4.match(line).to_s.delete!('/')
          # p ip_str
          if ip_str.start_with?('127.')
            next
          else
            # p ip_str
            ip_list.push(ip_str)
          end
        end
      end
    end
    ip_list
  end

  def addresses
    # ["first", "second", "third","forth"]
    @addrs = self.GetNetConfig
    @addrs
  end

  def items
    result = []
    addresses.each_with_index do |a, i|
      result << [Id(i), a]
    end
    result
  end

  def get_addr
    # return addresses[self.value[0]]
    value
  end

  def opt
    [:notify]
  end
end

class ACLTable < CWM::Table
  def initialize(target_name,tpg)
    @target_name = target_name
    @tpg_num = tpg
    @acls = generate_items()
   # @all_acls_hash = get_all_acls_hash()
  end

  def get_all_acls_hash
    $target_data.analyze()
    all_acls_hash = Hash.new()
    target_list = $target_data.get_target_list
    target = target_list.fetch_target(@target_name)
    tpg = target.get_default_tpg
    #we only has one acl group called "acls"
    if tpg != nil
      acls_group_hash = tpg.fetch_acls("acls")
    else
      err_msg = _("There are no TPGs in the target!")
      Yast::Popup.Error(err_msg)
    end
    if acls_group_hash != nil
      all_acls_hash = acls_group_hash.get_all_acls()
    end
    return all_acls_hash
  end

  def generate_items
    acls = Array.new()
    auth_str = ""
    all_acls_hash = get_all_acls_hash()
    all_acls_hash.each do |key,value|
      #p value
      lun_mappig_str = get_lun_mapping_str(value)
      auth_str = get_auth_str(value)
      if auth_str.empty? == true
        # add a space following None, becasue we need to -1 below
        auth_str = "None "
      end
      item = [rand(999), key, lun_mappig_str[0, lun_mappig_str.length - 1], auth_str[0, auth_str.length - 1]]
      acls.push(item)
    end
    return acls
  end

  # This function will return lun mapping str like: 0->1, 2->3
  def get_lun_mapping_str(acl_rule)
    lun_mappig_str = String.new()
    mapped_lun = acl_rule.get_mapped_lun()
    mapped_lun.each do |key, value|
      lun_mappig_str += value.fetch_mapped_lun_number  + "->" + value.fetch_mapping_lun_number + ","
    end
    return lun_mappig_str
  end

  # This function will return auth str, like "authentication by targets"
  def get_auth_str(acl_rule)
    auth_str = ""
    userid = acl_rule.fetch_userid
    password = acl_rule.fetch_password
    mutual_userid = acl_rule.fetch_mutual_userid
    mutual_password = acl_rule.fetch_mutual_password
    # Notice: when empty userid or password, it is " \n"(a space and \n)
    if (userid != " \n") && (password != " \n")
      auth_str += _("Authentication by Target,")
    end
    if (mutual_userid != " \n") && (mutual_password != " \n")
      auth_str += _("Authentication by Initiator,")
    end
    return auth_str
  end


  def get_selected()
    #puts "get_selected() called."
    #puts "@acls are:", @acls
    #p "self.value is:", self.value
    @acls.each do |item|
      #p "item is:", item
      if item[0] == self.value
        return item
      end
    end
  end

  def add_item(item)
    @acls.push(item)
    self.change_items(@acls)
  end

  def modify_item

  end

  def remove_item

  end

  def header
    [_('Initiator'), _('LUN Mapping'), _('Auth')]
  end

  def items
    @acls
  end

  def validate
    true
  end
end

class InitiatorNameInput < CWM::InputField
  def initialize(str)
    @config = str
  end

  def label
    _('Initiator Name:')
  end

  def init
    self.value = @config
  end
  def validate
    iscsi_name_max_length = 233
    if value.empty? == true
      err_msg = _("Initiator name can not be empty!")
      Yast::Popup.Error(err_msg)
      return false
    end

    if value.bytesize > iscsi_name_max_length
      err_msg = _("Initiator name can not be longger than 233 bytes!")
      Yast::Popup.Error(err_msg)
      return false
    end
    return true
  end

  def store
    @config = value
  end

  def get_value
    return @config
  end
end

class ImportLUNsCheckbox < ::CWM::CheckBox
  def initialize
    textdomain 'example'
  end

  def label
    _('Import LUNs from TPG')
  end

  # auto called from Yast
  def init
    self.value = true # TODO: read config
  end

  def store
    puts "IT IS #{value}!!!"
  end

  def handle
    puts 'Changed!'
  end

  def opt
    [:notify]
  end
end

class AddAclDialog < CWM::Dialog
  def initialize
    @initiator_name_input = InitiatorNameInput.new("")
    @import_luns = ImportLUNsCheckbox.new()
  end

  def init

  end

  def wizard_create_dialog
    Yast::UI.OpenDialog(layout)
    yield
  ensure
    Yast::UI.CloseDialog()
  end

  def title
    'Add an initiator'
  end

  def contents
    VBox(
        @initiator_name_input,
        @import_luns,
        HBox(
            PushButton(Id(:cancel), _('Cancel')),
            PushButton(Id(:ok), _('OK')),
        ),
    )
  end

  def should_open_dialog?
    true
  end

  def layout
    VBox(
        Left(Heading(Id(:title), title)),
        MinSize(70, 10, ReplacePoint(Id(:contents), Empty())),
    )
  end

  def run
    super
    return @initiator_name_input.get_value()
  end
end


class LUNMappingTable < CWM::Table

  def get_all_acls_hash
    $target_data.analyze()
    all_acls_hash = Hash.new()
    target_list = $target_data.get_target_list
    target = target_list.fetch_target(@target_name)
    tpg = target.get_default_tpg
    #we only has one acl group called "acls"
    if tpg != nil
      acls_group_hash = tpg.fetch_acls("acls")
    else
      err_msg = _("There are no TPGs in the target!")
      Yast::Popup.Error(err_msg)
    end
    if acls_group_hash != nil
      all_acls_hash = acls_group_hash.get_all_acls()
    end
    return all_acls_hash
  end

  # This function will return lun mapping str like: 0->1, 2->3
  def get_lun_mapping_str(acl_rule)
    lun_mappig_str = String.new()
    mapped_lun = acl_rule.get_mapped_lun()
    mapped_lun.each do |key, value|
      lun_mappig_str += value.fetch_mapped_lun_number  + "->" + value.fetch_mapping_lun_number + ","
    end
    return lun_mappig_str
  end


  def initialize()

  end

  def init

  end

  def generate_items
    @mapping = Array.new()
    return @mapping
  end

  def add_item(item)
    #@acls.push(item)
    #self.change_items(@acls)
  end

  def modify_item

  end

  def remove_item

  end

  def header
    [_('Initiator LUN'), _('Target LUN')]
  end

  def items
    return generate_items()
  end

  def validate
    true
  end
end

class EditLUNMappingDialog < CWM::Dialog
  def initialize(item)
    p "In EditLUNMappingDialog, we got:", item
    @lun_mapping_table = LUNMappingTable.new()
  end


  def wizard_create_dialog
    Yast::UI.OpenDialog(layout)
    yield
  ensure
    Yast::UI.CloseDialog()
  end

  def title
    'Edit LUN mapping'
  end

  def contents
    VBox(
        @lun_mapping_table,
        HBox(
            PushButton(Id(:add), _('Add')),
            PushButton(Id(:delete), _('Delete')),
            PushButton(Id(:ok), _('OK')),
            PushButton(Id(:abort), _('Abort')),
        ),
    )
  end

  def should_open_dialog?
    true
  end

  def layout
    VBox(
        Left(Heading(Id(:title), title)),
        MinSize(50, 20, ReplacePoint(Id(:contents), Empty())),
    )
  end

  def run
    super
    #return @initiator_name_input.get_value()
  end
end


#Class to handle initiator acls, will shown after creating or editing targets.
class InitiatorACLs < CWM::CustomWidget
  def initialize(target_name, tpg_num)
    self.handle_all_events = false
    @target_tpg = tpg_num
    @target_name_input = TargetNameInput.new(target_name)
    @target_portal_input = PortalGroupInput.new(@target_tpg)
    @acls_table = ACLTable.new(target_name,tpg_num.to_i)
    @add_acl_dialog = AddAclDialog.new()
    #@edit_lun_mapping_dialog = EditLUNMappingDialog.new(nil)
    #@all_acls_hash = nil
  end

  def init
    @target_name_input.disable()
    @target_portal_input.disable()
  end

  def opt
    [:notify]
  end

  def contents
    VBox(
        HBox(
            @target_name_input,
            @target_portal_input,
        ),
        @acls_table,
        HBox(
            PushButton(Id(:add), _('Add')),
            PushButton(Id(:edit_lun), _('Edit LUN')),
            PushButton(Id(:edit_auth), _('Edit Auth')),
            PushButton(Id(:delete), _('Delete')),
            PushButton(Id(:copy), _('Copy')),
        )
    )
  end

  def validate
    ret = Yast::Popup.ErrorAnyQuestion(_("Warning"), _("test message"), _("Yes"), _("No"), :focus_yes)
    if ret == true
      return true
    else
      return false
    end
    return true
  end

  def handle(event)
    case event["ID"]
      when :add
        initiator_name = @add_acl_dialog.run
        if initiator_name.empty? != true
          item = Array.new()
          item.push(rand(9999))
          item.push(initiator_name)
          item.push("")
          item.push("None")
          @acls_table.add_item(item)
        end
      when :edit_lun
        #@edit_lun_mapping_dialog.run
        item = @acls_table.get_selected()
        p item
        edit_lun_mapping_dialog = EditLUNMappingDialog.new(item)
        ret = edit_lun_mapping_dialog.run
  end
    nil
  end

  def help
    "demo help in InitaitorACLs"
  end
end

# This class is used for both adding a target and editing a target
class AddTargetWidget < CWM::CustomWidget
  include Yast
  include Yast::I18n
  include Yast::UIShortcuts
  include Yast::Logger

  # Fill nil when add a target or fill the name of the target to be edited
  def initialize(target_name)
    #puts "AddTargetWidget initialize() called."
    self.handle_all_events = true
    #self.handle_all_events = false
    @iscsi_name_length_max = 223
    @back_storage = nil
    @target_name = nil
    # @target_info used to return target name, portal number, etc to the caller, in order to create ACLs
    @target_info = Array.new
    # luns contains the luns would be shown in the lun table
    luns = nil
    # if mode == "new", need to create targets and luns, if mode == "edit", just change the target config
    @mode = nil
    time = Time.new
    date_str = time.strftime('%Y-%m')
    if target_name == nil
      @mode = 'new'
      @target_name_input_field = TargetNameInput.new('iqn.' + date_str + '.com.example')
      @target_identifier_input_field = TargetIdentifierInput.new(SecureRandom.hex(10))
      # @target_identifier_input_field = TargetIdentifierInput.new("123")
      @target_portal_group_field = PortalGroupInput.new(1)
      @target_port_num_field = TargetPortNumberInput.new(3260)
    else
      @mode = 'edit'
      printf("Editing target %s.\n", target_name)
      tpg_num = 0
      target_list = $target_data.get_target_list
      target = target_list.fetch_target(target_name)
      # tpg = target.fetch_tpg()
      tpg = target.get_default_tpg
      #puts 'tpg is:'
      #p tpg
      # we add a default target portal group = 1 if no tpgs exist.
      if tpg == nil
        #puts 'in if, tpg is'
        #p tpg
        tpg_num = rand(10)
        puts tpg_num
        cmd = 'targetcli'
        p1 = 'iscsi/' + target_name + '/ create tag=' + tpg_num.to_s
        begin
          Cheetah.run(cmd, p1)
        rescue Cheetah::ExecutionFailed => e
          Yast::Popup.Error(e.stderr) unless e.stderr.nil?
        end
        $target_data.analyze
        target = target_list.fetch_target(target_name)
      end

      if tpg != nil
        #puts 'in else,tpg is:'
        #p tpg
        target = target_list.fetch_target(target_name)
        tpg_num = target.get_default_tpg.fetch_tpg_number
      end

      printf("tpg_num is %d.\n", tpg_num)
      luns = target.get_default_tpg.get_luns_array
      # p luns
      @target_name_input_field = TargetNameInput.new(target_name)
      # just use a empty string here to adapt the string parameter requirement
      @target_identifier_input_field = TargetIdentifierInput.new('')
      @target_portal_group_field = PortalGroupInput.new(tpg_num)
      @target_port_num_field = TargetPortNumberInput.new(3260)
    end

    @IP_selsection_box = IpSelectionComboBox.new
    @target_bind_all_ip_checkbox = BindAllIP.new
    @use_login_auth = UseLoginAuth.new
    @lun_table_widget = LUNsTableWidget.new(luns)
  end

  def opt
    [:notify]
  end

  def contents
    VBox(
      HBox(
        @target_name_input_field,
        @target_identifier_input_field,
        @target_portal_group_field
      ),
      HBox(
        @IP_selsection_box,
        @target_port_num_field
      ),
      VBox(
        @target_bind_all_ip_checkbox,
        @use_login_auth
      ),
      @lun_table_widget
    )
  end

  def validate
    puts "Validate in AddTargetWidget is called."
    if @mode == 'new'
      cmd = 'targetcli'
      p1 = 'iscsi/ create'
      if @target_name_input_field.get_value.bytesize > @iscsi_name_length_max
        @target_name = @target_name_input_field.get_value
      else
        @target_name = @target_name_input_field.get_value + ':' + @target_identifier_input_field.get_value
      end
      begin
        Cheetah.run(cmd, p1, @target_name)
      rescue Cheetah::ExecutionFailed => e
        if e.stderr != nil
          err_msg = _('Can not create the target with target name: ') + \
                    @target_name + _(", plese check target name.\n") + \
                    _('Additional information: ') + e.stderr
          Yast::Popup.Error(err_msg)
          return false
        end
      end
      target_tpg = @target_portal_group_field.value.to_s
      # Yast only support one TPG, targetcli will create a default tpg =1, if users provided another tpg number,
      # we need to delete tpg=1, then create another tpg based on the user provided number
      if target_tpg != '1'
        p1 = 'iscsi/' + @target_name + '/ delete tag=1'
        p2 = 'iscsi/' + @target_name + '/ create tag=' + target_tpg
        begin
          Cheetah.run(cmd, p1)
        rescue Cheetah::ExecutionFailed => e
          unless e.stderr.nil?
            err_msg = _('Target Portal Group number ') + target_tpg + _(' is provided to replace the defalult tpg') \
            + _('Failed to delete the default tpg, please consider to re-create the target and check') \
            + _('whether someone called targetcli manually')
            Yast::Popup.Error(err_msg)
            return false
          end
        end
        begin
          Cheetah.run(cmd, p2)
        rescue Cheetah::ExecutionFailed => e
          unless e.stderr.nil?
            err_msg = _('Failed to create Target Portal Group ') + target_tpg \
            + _('The target is create, in the meanwhile, please delete it if needed.') \
            + _('Or a defalut target portal group 1 will be added to the target when you edit it.')
            Yast::Popup.Error(err_msg)
            return false
          end
        end
      end
      @lun_table_widget.set_target_info(@target_name, target_tpg)
      @target_info.push(@target_name)
      @target_info.push(target_tpg)
      return true
    end

    if @mode == 'edit'
      @target_name = @target_name_input_field.get_value
      target_tpg = @target_portal_group_field.value.to_s
      @lun_table_widget.set_target_info(@target_name, target_tpg)
    end
    @target_info.push(@target_name)
    @target_info.push(target_tpg)
    true
  end

  # used to return target info like target name, portal number to caller, for example, to craete ACLs
  def get_target_info
    info = @target_info
    return info
  end

  def handle(event)
    puts "Handle() in AddTargetWidget is called."
    # puts event
    case event['ID']
      when :next
        puts "In next"
        return "test1111"
    end
    puts "here"
    nil
  end
end

class TargetTable < CWM::Table
  def initialize
    # puts "initialize() is called."
    # functions like initialize and items would be called multiple times by its
    # container(and its container) working not properly
    # That's the reason why we need @items_need_refresh to control that. We should remove @items_need_refresh
    # when CWM work well. We don't need locks to protect it.
    # @items_need_refresh = false
    @targets = generate_items()
    @targets_names = $target_data.get_target_names_array
  end

  def init
    # puts 'init() is called.'
  end

  def generate_items
    @targets_names = $target_data.get_target_names_array
    item_array = nil
    @targets = Array.new
    @targets_names.each do |elem|
      @targets.push([rand(9999), elem, 1, 'Enabled'])
    end
    item_array = @targets
    return item_array
  end

  def header
    [_('Targets'), _('Portal Group'), _('TPG Status')]
  end

  def items
    #generate_items()
    @targets
  end

  def get_selected
    p @targets
    p self.value
    @targets.each do |target|
      p target
      if target[0] == self.value
        return target
      end
    end
    return nil
  end

  # this function will remove a target from the table.
  def remove_target_item(id)
    # p @targets
    @targets.each do |elem|
      # printf("id is %d.\n", id)
      if elem[0] == id
        # printf("elem[0] is %d.\n", elem[0]);
        # p elem
      end
      @targets.delete_if { |elem| elem[0] == id }
    end
    update_table
  end

  def update_table
    # puts "update_table() is called."
    $target_data.analyze
    @targets_names = $target_data.get_target_names_array
    change_items(generate_items)
  end
end

class TargetsTableWidget < CWM::CustomWidget
  include Yast
  include Yast::I18n
  include Yast::UIShortcuts
  include Yast::Logger
  def initialize
    # puts "Initialized a TargetsTableWidget class"
    # p caller
    self.handle_all_events = true
    @target_table = TargetTable.new
    @add_target_page = nil
    @edit_target_page = nil
    # target_info will store target name, portal, etc
    @target_info = nil
  end

  def opt
    [:notify]
  end

  def contents
    VBox(
      Id(:targets_table),
      @target_table,
      HBox(
        PushButton(Id(:add), _('Add')),
        PushButton(Id(:edit), _('Edit')),
        PushButton(Id(:delete), _('Delete'))
      )
    )
  end

  def create_ACLs_dialog(info)
    if info.empty? != true
      @initiator_acls = InitiatorACLs.new(info[0], info[1])
      contents = VBox(@initiator_acls)
      Yast::Wizard.CreateDialog
      CWM.show(contents, caption: _('Modify initiators ACLs'))
      Yast::Wizard.CloseDialog
    end
  end

  def handle(event)
    # puts event
    # we put @target_table.update_table() in every case than outside the "case event", because handle would be called
    # in it's container, that will cause an unexpected update table.
    case event['ID']
      when :add
        @add_target_page = AddTargetWidget.new(nil)
        contents = VBox(@add_target_page, HStretch(), VStretch())
        Yast::Wizard.CreateDialog
        ret = CWM.show(contents, caption: _('Add iSCSI Target'))
        puts "in :add, the ret is :"
        puts ret
        Yast::Wizard.CloseDialog
        @target_table.update_table
        info = @add_target_page.get_target_info()
        create_ACLs_dialog(info)
      when :edit
        puts 'Clicked Edit button!'
        target = @target_table.get_selected
        puts "in :edit, target is:"
        p target
        if target != nil
          @edit_target_page = AddTargetWidget.new(target[1])
          contents = VBox(@edit_target_page, HStretch(), VStretch())
          Yast::Wizard.CreateDialog
          CWM.show(contents, caption: _('Edit iSCSI Target'))
          Yast::Wizard.CloseDialog
        end
        @target_table.update_table
        info = @edit_target_page.get_target_info()
        create_ACLs_dialog(info)
      when :delete
        id = @target_table.get_selected
        # puts "Clicked Delete button"
        printf("The selected value is %s.\n", id)
        # @target_table.remove_target_item(id)
        @target_table.update_table
    end
    nil
  end

  def help
    _('demo help')
  end
end

class LUNTable < CWM::Table
  def initialize(init_luns)
    # puts "initialize a LUNTable"
    # p caller
    # @luns will store all luns exsisted and will be created
    @luns = init_luns
    # @luns_add will store the luns will be created, will not store any exsisted luns.
    @luns_added = []
    @luns = generate_items
    @target_name = nil
    @target_tpg = nil
  end

  def set_target_info(name, tpg)
    @target_name = name
    @target_tpg = tpg
    # puts 'in set_target_name'
    # p @target_name
    # p @target_tpg
  end

  def generate_items
    # p "generate_items is called."
    items_array = []
    if !@luns.nil?
      return @luns
    else
      @luns = []
    end
    @luns
  end

  def header
    [_('LUN'), _('Name'), _('Path')]
  end

  def items
    @luns
  end

  def get_selected
    value
  end

  # This function will return the array @luns, LUNsTableWidget will use this to decide the lun number
  def get_luns
    @luns
  end

  # This function will return the array @luns_added, means the new luns need to create
  def get_new_luns
    @luns_added
  end

  # this function will add a lun in the table, the parameter item is an array
  def add_lun_item(item)
    @luns.push(item)
    @luns_added.push(item)
    update_table(@luns)
  end

  # this function will delete a LUN both in a target tpg#n/luns and /backstore/fileio or block via targetcli
  def delete_lun(lun_str); end

  # this function will remove a lun from the table, will try to delete it from @luns_added and @luns
  def table_remove_lun_item(id)
    @luns_added.delete_if { |item| item[0] == id }
    @luns.delete_if { |item| item[0] == id }
    update_table(@luns)
  end

  def validate
    puts 'validate() in LUN_table is called.'
    failed_storage = String.new
    p @luns_added
    @luns_added.each do |lun|
      cmd = 'targetcli'
      if lun[2].empty? == false
        case lun[4]
          when "file"
            p1 = 'backstores/fileio create name=' + lun[2] + ' file_or_dev=' + lun[3]
            p2 = 'iscsi/' + @target_name + '/tpg' + @target_tpg + "/luns/ create " + \
                 'storage_object=/backstores/fileio/' + lun[2]
          when "blockSpecial"
            p1 = 'backstores/block create name=' + lun[2] + ' dev=' + lun[3]
            p2 = 'iscsi/' + @target_name + '/tpg' + @target_tpg + "/luns/ create " + \
                 'storage_object=/backstores/block/' + lun[2]
        end
        # create backstores using the backstore provided in lun[4]  if lun[2] is not empty.
        begin
          Cheetah.run(cmd, p1)
        rescue Cheetah::ExecutionFailed => e
          if e.stderr != nil
            failed_storage += (lun[3] + "\n")
            next
          end
        end
      else
        # command to create the lun in target tpg, no need to craete backstores if lun[2] is empty
        p2 = 'iscsi/' + @target_name + '/tpg' + @target_tpg + "/luns/ create " + 'storage_object=' + lun[3]
      end
      if lun[1].to_s != "-1"
        p2 += (' lun=' + lun[1].to_s)
      end
      begin
        Cheetah.run(cmd, p2)
      rescue Cheetah::ExecutionFailed => e
        if e.stderr != nil
          failed_storage += (lun[3] + "\n")
          table_remove_lun_item(lun[0])
          update_table(@luns)
          next
        end
      end
    end
    #Pop up messages if any failures.
    if failed_storage.empty? == false
      err_msg = _("Failed to create LUNs with such backstores:\n") + failed_storage + \
                  _("Please check whether the backstore or LUN number is in use, name is valid.") + \
                  _("Then delete the failed LUNs.\n")
      Yast::Popup.Error(err_msg)
      return false
      $target_data.analyze()
    end
    $target_data.analyze()
    true
  end


  def update_table(luns)
    puts "in update_table, luns are:"
    puts luns
    change_items(luns)
  end
end

class LunNumInput < CWM::IntField
  def initialize(num)
    @config = num
  end

  def label
    _("LUN Number(left '-1' here to auto generate)")
  end

  def init
    #self.value = @config
  end

  def store
    @config = value
  end

  def minimum
    -1
  end

  def get_value
    return self.value
  end
end

class LUNPathInput < CWM::InputField
  def initialize(str)
    puts "In initialize, str is :"
    puts str
    @config = str
  end

  def label
    _('LUN Path')
  end

  def validate
    if value.empty?
      Yast::UI.SetFocus(Id(widget_id))
      Yast::Popup.Error(_('LUN path cannot be empty.'))
      false
    else
      true
    end
  end

  def init
    #self.value = @config
  end

  def store
    @config = value
  end

  def get_value
    puts "In get_value(), value is :"
    puts self.value
    return self.value
  end

  def set_value(path)
    self.value = path
  end
end

class LunNameInput < CWM::InputField
  def initialize(str)
    @config = str
  end

  def label
    _('LUN Name(auto generated when empty)')
  end

  def validate
    true
  end

  def init
    #self.value = @config
  end

  def store
    @config = value
  end

  def get_value
    value
  end
end

# This widget contains Lun path input and lun path browsing
class LUNPathEdit < CWM::CustomWidget
  include Yast
  include Yast::I18n
  include Yast::UIShortcuts
  include Yast::Logger
  def initialize
    self.handle_all_events = true
    @path = nil
    @lun_path_input = LUNPathInput.new("")
  end

  def contents
    HBox(
      @lun_path_input,
      PushButton(Id(:browse), _('Browse'))
    )
  end

  def get_value
    return @lun_path_input.value
  end

  def store; end

  def validate
    file = @lun_path_input.value.to_s
    if file.empty?
      Yast::Popup.Error(_('LUN Path can not be empty!'))
      return false
    end
    if File.exist?(file) == false
      Yast::Popup.Error(_('The file does not exist!'))
      @lun_path_input.value = nil
      return false
    end
    file_type = File.ftype(file)
    if (file_type != 'blockSpecial') && (file_type != 'file')
      Yast::Popup.Error(_('Please provide a normal file or a block device.'))
      @lun_path_input.value = nil
      return false
    end
    true
  end

  def is_valid
    file = @lun_path_input.value.to_s
    if file.empty?
      return false
    end
    if File.exist?(file) == false
      return false
    end
    file_type = File.ftype(file)
    if (file_type != 'blockSpecial') && (file_type != 'file')
      return false
    end
    return true
  end

  def handle(event)
    case event['ID']
    when :browse
      file = UI.AskForExistingFile('/', '', _('Select a file or device'))
      unless file.nil?
        # @path = file
        # @lun_path_input.set_value(file)
        @lun_path_input.set_value(file)
      end
    #when :ok

    end
    nil
  end

  def help; end
end

# This is a class to config LUN path, number and name, used in LUNDetailsWidget contents
class LUNConfig < CWM::CustomWidget
  def initialize
    @lun_num_input = LunNumInput.new(nil)
    @lun_path_edit = LUNPathEdit.new
    @lun_name_input = LunNameInput.new(nil)
    @lun_info = nil
  end

  def contents
    VBox(
      @lun_num_input,
      @lun_path_edit,
      @lun_name_input,
      HBox(
        PushButton(Id(:cancel), _('Cancel')),
        PushButton(Id(:ok), _('OK'))
      )
    )
  end

  def store
    # puts "store is called."
  end

  def validate
    # puts "validate is called."
    # printf("lun num is %d.\n", @lun_num_input.get_value)
    # printf("lun name is %s.\n", @lun_name_input.get_value)
    # printf("lun path is %s.\n", @lun_path_edit.get_value)
    #puts "@lun_path_edit.is_valid is :"
    #puts @lun_path_edit.is_valid
    if @lun_path_edit.is_valid == true
      @lun_info = Array.new
      @lun_info.push(@lun_num_input.get_value)
      @lun_info.push(@lun_name_input.get_value)
      @lun_info.push(@lun_path_edit.get_value)
    end
    true
  end

  def handle
    # puts "handle is called."
  end

  def get_lun_info
    @lun_info
  end

  def help; end
end

class LUNDetailsWidget < CWM::Dialog
  def initialize
    @lun_config = LUNConfig.new
  end

  def title
    'Test Dialog'
  end

  def wizard_create_dialog
    Yast::UI.OpenDialog(layout)
    yield
  ensure
    Yast::UI.CloseDialog()
  end

  def contents
    VBox(
      @lun_config
    )
  end

  def should_open_dialog?
    true
  end

  def layout
    VBox(
      HSpacing(50),
      Left(Heading(Id(:title), title)),
      VStretch(),
      VSpacing(1),
      MinSize(50, 18, ReplacePoint(Id(:contents), Empty())),
      VSpacing(1),
      VStretch()
    )
  end

  def run
    super
    @lun_config.get_lun_info
  end
end

class LUNsTableWidget < CWM::CustomWidget
  include Yast
  include Yast::I18n
  include Yast::UIShortcuts
  include Yast::Logger
  def initialize(luns)
    self.handle_all_events = true
    @lun_table = LUNTable.new(luns)
    @lun_details = LUNDetailsWidget.new
    @target_name = nil
  end

  def contents
    VBox(
      @lun_table,
      HBox(
        PushButton(Id(:add), _('Add')),
        PushButton(Id(:edit), _('Edit')),
        PushButton(Id(:delete), _('Delete'))
      )
    )
  end

  # This function pass target name from AddTargetWidget to lun table
  def set_target_info(name, tpg)
    @lun_table.set_target_info(name, tpg)
  end

  # This function will return new luns, aka the newly added luns which needed to be created in tpg#N/luns
  def get_new_luns
    @lun_table.get_new_luns
  end

  def create_luns_backstores
    @lun_table.create_luns_backstore
  end

  def opt
    [:notify]
  end

  def validate
    # puts "Validate() in LunsTableWidget called.\n"
    true
  end

  def handle(event)
    # puts event
    case event['ID']
    when :add
      ret = @lun_details.run
      if ret != nil
        lun_number = ret[0]
        lun_name = ret[1]
        file = ret[2]
        if !file.nil? && (File.exist?(file) == true)
          @lun_table.add_lun_item([rand(9999), lun_number, lun_name, file, File.ftype(file)])
        end
        puts 'Got the lun info:'
        puts ret
      end
    when :edit
      file = UI.AskForExistingFile('/', '', _('Select a file or device'))
      unless file.nil?
        luns = @lun_table.get_luns
        lun_number = rand(100)
        # lun path to lun name. Like /home/lszhu/target.raw ==> home_lszhu_target.raw
        lun_name = file[1, file.length].gsub(/\//, '_')
        @lun_table.add_lun_item([rand(9999), lun_number, lun_name, file, File.ftype(file)])
      end
    end
    nil
  end

  def help
    _('demo help')
  end
end