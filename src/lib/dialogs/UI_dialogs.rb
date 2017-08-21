# Simple example to demonstrate object API for CWM

#require_relative "example_helper"
require './src/lib/helps/example_helper.rb'
require './src/lib/TargetData.rb'
require "cwm/widget"
require "ui/service_status"
require "yast"
require "cwm/table"
require "yast2/execute"

Yast.import "CWM"
Yast.import "CWMTab"
Yast.import "TablePopup"
Yast.import "CWMServiceStart"
Yast.import "Popup"
Yast.import "Wizard"
Yast.import "CWMFirewallInterfaces"
Yast.import "SuSEFirewall"
Yast.import "Service"
Yast.import "CWMServiceStart"
Yast.import "UI"
Yast.import "TablePopup"

class NoDiscoveryAuth_widget < ::CWM::CheckBox
  def initialize
    textdomain "example"
  end
  def label
    _("No Discovery Authentication")
  end
#auto called from Yast
  def init
    self.value = true #TODO read config
  end

  def store
    puts "IT IS #{value}!!!"
  end

  def handle 
    puts "Changed!"
  end

  def opt
    [:notify]
  end
end

class BindAllIP < ::CWM::CheckBox
  def initialize()
    textdomain "example"
  end
  def label
    _("Bind all IP addresses")
  end
#auto called from Yast
  def init
    self.value = true #TODO read config
  end

  def store
    puts "IT IS #{value}!!!"
  end

  def handle 
    puts "Changed!"
  end

  def opt
    [:notify]
  end
end

class UseLoginAuth < ::CWM::CheckBox
  def initialize()
    textdomain "example"
  end
  def label
    _("Use Login Authentication")
  end
#auto called from Yast
  def init
    self.value = true #TODO read config
  end

  def store
    puts "IT IS #{value}!!!"
  end

  def handle 
    puts "Changed!"
  end

  def opt
    [:notify]
  end
end


class Auth_by_Initiators_widget < ::CWM::CheckBox
  def initialize
    textdomain "example"
  end
  def label
    _("Authentication by initiators.\n")
  end
#auto called from Yast
  def init
    self.value = true #TODO read config
  end

  def store
    puts "IT IS #{value}!!!"
  end

  def handle 
    puts "Changed!"
  end

  def opt
    [:notify]
  end
end


class Auth_by_Targets_widget < ::CWM::CheckBox
  def initialize
    textdomain "example"
  end
  def label
    _("Autnentication by Targets")
  end
#auto called from Yast
  def init
    self.value = true #TODO read config
  end

  def store
    puts "IT IS #{value}!!!"
  end

  def handle 
    puts "Changed!"
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
    _("Username:")
  end

  def init
    self.value = @config
    printf("Username InputField init, got default value %s.\n",@config)
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
    _("Password:")
  end

  def init
    self.value = @config
    printf("Password InputField init, got default value %s.\n",@config)
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
    _("Mutual Username:")
  end

  def init
    self.value = @config
    printf("Mutual Username InputField init, got default value %s.\n",@config)
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
    _("Mutual Password:")
  end

  def init
    self.value = @config
    printf("Mutual Password InputField init, got default value %s.\n",@config)
  end

  def store
    @config = value
    printf("Mutual Password Inputfield will store the value %s.\n", @config)
  end
end

module Yast
  class ServiceTab < ::CWM::Tab
    #@fire_wall_service = nil
    include Yast::I18n
    include Yast::UIShortcuts
    def initialize
     #Yast.import "SuSEFirewall"
      self.initial = true
      @service = Yast::SystemdService.find("targetcli")
      @service_status = ::UI::ServiceStatus.new(@service, reload_flag: true, reload_flag_label: :restart)
      #self.Read()
      #SuSEFirewall.Read()
    end

    def Read()
      SuSEFirewall.Read()
    end
    def contents
      HBox(
         ::CWM::WrapperWidget.new(
           CWMFirewallInterfaces.CreateOpenFirewallWidget("services" => ["service:target"]),
           id: "firewall"
         ),
        @service_status.widget
       )
    end
  
    def label
      _("Service")
    end
  end
end
class GlobalTab < ::CWM::Tab
  def initialize
    self.initial = true
  end

  def contents
    VBox(
      #HStretch(),
      VStretch(),
      NoDiscoveryAuth_widget.new,
      Auth_by_Targets_widget.new,
      HBox(
        UserName.new("test username"),
        Password.new("test password")
      ),
      Auth_by_Initiators_widget.new,
      HBox(
        MutualUserName.new("test mutual username"),
        MutualPassword.new("test mutual password")
      )
    )
  end

  def label
    _("Global")
  end
end


class TargetsTab < ::CWM::Tab
  def initialize
    @target_table_widget = TargetsTableWidget.new
    #puts "Initialized a TargetsTab class."
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
    _("Targets")
  end
end


class TargetNameInput < CWM::InputField
  def initialize(str)
    @config = str
    @iscsi_name_length_max = 233
  end

  def label
    _("Target")
  end

 def validate
   if value.empty?
     Yast::UI.SetFocus(Id(widget_id))
     Yast::Popup.Error(_("Target name cannot be empty."))
     false
   elsif value.bytesize > @iscsi_name_length_max
     Yast::UI.SetFocus(Id(widget_id))
     Yast::Popup.Error(_("Target name cannot be longger than 223 bytes."))
     false
   else
     true
   end
 end
 
  def init
    self.value = @config
    printf("TargeteName InputField init, got default value %s.\n",@config)
  end

  def store
    @config = value
    printf("TargetName Inputfield will store the value %s.\n", @config)
  end
end

class TargetIdentifierInput < CWM::InputField
  def initialize(str)
    @config = str
  end

  def label
    _("Identifier")
  end

  def init
    self.value = @config
    #printf("Target Identifier InputField init, got default value %s.\n",@config)
  end

  def store
    @config = value
    #printf("Target Identifier Inputfield will store the value %s.\n", @config)
  end
end

class PortalGroupInput < CWM::IntField
  def initialize(str)
    @config = str
  end

  def label
    _("Portal group")
  end

  def init
    self.value = @config
    #printf("Target Portal Group InputField init, got default value %s.\n",@config)
  end

  def store
    @config = value
    #printf("Target Portal Group will store the value %s.\n", @config)
  end

  def minimum
    return 0
  end
end

class TargetPortNumberInput < CWM::IntField
  def initialize(str)
    @config = str
  end

  def label
    _("Port Number")
  end

  def init
    self.value = @config
    #printf("Target port number InputField init, got default value %s.\n",@config)
  end

  def store
    @config = value
    #printf("Target port number will store the value %s.\n", @config)
  end

  def minimum
    return 0
  end
end


class IpSelectionComboBox < CWM::ComboBox
  def initialize()
    @addrs = nil
    #@config = myconfig
  end

  def label
    _("IP Address:")
  end

  def init
    #self.value = @config.value
  end

  def store
    #@config.value = value
    #puts self.value
    #puts get_addr
  end
  
  def GetNetConfig
     ip_list = Array.new
     re_ipv4 = Regexp.new(/[\d+\.]+\//)
     re_ipv6 = Regexp.new(/[\w+\:]+\//)
     ret = Yast::Execute.locally("ip", "a", stdout: :capture)
     ip = ret.split("\n")
     ip.each do |line|
       line = line.strip
       if(line.include?("inet") && !line.include?("deprecated")) # don't show deprecated IPs
         if line.include?("inet6")
           ip_str = re_ipv6.match(line).to_s.gsub!("/","")
           if ip_str.start_with?("::1")
             next
           elsif ip_str.start_with?("fe80:")
             next
           else
             #p ip_str
             ip_list.push(ip_str)
           end
         else
           #delete "/", and drop 127.x.x.x locall address
           ip_str = re_ipv4.match(line).to_s.gsub!("/","")
           #p ip_str
           if ip_str.start_with?("127.")
             next
           else
            # p ip_str
             ip_list.push(ip_str)
           end
         end
       end
     end
     return ip_list
  end

  def addresses
    #["first", "second", "third","forth"]
    @addrs = self.GetNetConfig
    return @addrs
  end
  
  def items
    result = []
    addresses.each_with_index do |a, i|
      result << [ Id(i), a]
    end
    result
  end

  def get_addr
   #return addresses[self.value[0]]
   return self.value
  end


  def opt
    [:notify]
  end
end


class AddTargetWidget < CWM::CustomWidget
  include Yast
  include Yast::I18n
  include Yast::UIShortcuts
  include Yast::Logger
  def initialize
    self.handle_all_events = true
    #printf("initialized an AddTargetWidget.11111111111111111111\n ")
    @iscsi_name_length_max = 223
    @back_storage = nil
    @luns_to_create = Array.new
    time = Time.new
    date_str = time.strftime("%Y-%m")
    @target_name_input_field = TargetNameInput.new("iqn." + date_str + ".com.example")
    @target_identifier_input_field = TargetIdentifierInput.new(SecureRandom.hex(10))
    @target_portal_group_field = PortalGroupInput.new(1)
    @target_port_num_field = TargetPortNumberInput.new(3260)
    @IP_selsection_box = IpSelectionComboBox.new
    @target_bind_all_ip_checkbox = BindAllIP.new
    @use_login_auth = UseLoginAuth.new
    @lun_table = LUNsTableWidget.new
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
        @target_port_num_field,
      ),
      VBox(
        @target_bind_all_ip_checkbox,
        @use_login_auth,
      ),
      @lun_table,
    )
  end

  def create_target
    cmd = "targetcli"
    p1 = "iscsi/ create"
    if @target_name_input_field.value.bytesize > @iscsi_name_length_max
      p2 = @target_name_input_field.value
    else
      p2 = @target_name_input_field.value+":"+@target_identifier_input_field.value.to_s
    end
    ret = Yast::Execute.locally(cmd, p1, p2, stdout: :capture)
  end

  #this function will fill the array luns_to_create with all paths of luns to be created
  def prepare_luns_list()
    #@luns_to_create = Array.new
    luns = @lun_table.get_luns_to_create()
    #p luns
    luns.each do |lun|
      @luns_to_create.push(lun[2])
    end
    p @luns_to_create
  end
  def create_luns
    p "create_luns() is called.\n"
  end

  def store
    self.create_target
    #self.create_luns
  end

  def handle(event)
    puts event 
    case event["ID"]
      when :next
        #puts "clicked Next."
        #puts @target_name_input_field.value
        self.prepare_luns_list
        
        if @target_portal_group_field.value.to_s.empty?
          self.popup_warning_dialog("Error", "Portal group can not be empty")
        end
    end
    nil
  end
end

class TargetTable < CWM::Table
  def initialize()
   # puts "initialize a TargetTable"
    #p caller
    @targets = Array.new
    @targets_names = $target_data.get_target_names_array
    @targets = generate_items()
    #@targets.push([3, "iqn.2017-04.suse.com.lszhu", 1, "Enabled"])
    #p @targets_names
  end

  def generate_items
    #puts "generate_items is called.\n"
    items_array = Array.new
    @targets_names.each do |elem|
      items_array.push([rand(9999), elem, 1 , "Enabled"])
    end
    return items_array
  end

  def header
    [_("Targets"), _("Portal Group"), _("TPG Status")]
  end

  def items
    #@targets = generate_items()
    @targets
  end

  def get_selected
    return self.value
  end

 #this function will add a target in the table, the parameter item is an array
  def add_target_item(item)
  end

  #this function will remove a target from the table.
  def remove_target_item(id)
    #p @targets
    @targets.each do |elem|
      #printf("id is %d.\n", id)
      if elem[0] == id
        #printf("elem[0] is %d.\n", elem[0]);
        p elem
      end
      @targets.delete_if{|elem| elem[0] == id}
    end
       p @targets
       update_table(@targets)
       
  end
  
  def update_table(items)
    #@targets.push([1, "iqn.2017-04.suse.com.test", 1, "Enabled"])
    self.change_items(items)
  end
end


class TargetsTableWidget < CWM::CustomWidget
  include Yast
  include Yast::I18n
  include Yast::UIShortcuts
  include Yast::Logger
  def initialize
    #puts "Initialized a TargetsTableWidget class"
    #p caller
    self.handle_all_events = true
    @target_table = TargetTable.new
    #p "@target_table is"
    #p @target_table
    @add_target_page = AddTargetWidget.new
  end

  def contents
    VBox(
      #Table(
        # Id(:targets_table),
         #Header("Targets", "Portal Group", "TPG Status"),
           #[
             #Item(Id(1), "iqn.2017-04.suse.com.lszhu.target.sn.abcdefghisdljhlshjl", 1,"Enabled"),
           #]
       #),
       @target_table,
       HBox(
         PushButton(Id(:add), _("Add")),
         PushButton(Id(:edit), _("Edit")),
         PushButton(Id(:delete), _("Delete"))
       )
  )
  end

  def handle(event)
    puts event
    case event["ID"]
      when :add
        puts "Clicked Add button!"
        #puts Yast::UI.QueryWidget(Id(:targets_table), :CurrentItem)
        #puts Yast::UI.QueryWidget(Id(:targets_table), :Items)
        contents = VBox(@add_target_page,HStretch(),VStretch())

        Yast::Wizard.CreateDialog
        CWM.show(contents, caption: _("Add iSCSI Target"))
        Yast::Wizard.CloseDialog
        @add_target_page = AddTargetWidget.new
      when :delete
        id = @target_table.get_selected()
        puts "Clicked Delete button"
        printf("The selected value is %s.\n", id)
        @target_table.remove_target_item(id) 
         
     end
     nil
  end

  def help
    _("demo help")
  end
end

class LUNTable < CWM::Table
  def initialize(target_name)
    #puts "initialize a LUNTable"
    #p caller
    # @luns will store all luns exsisted and will be created
    @luns = Array.new
    # @luns_add will store the luns will be created, will not store any exsisted luns.
    @luns_added = Array.new
    @luns = generate_items()
  end

  def generate_items
    #puts "generate_items is called.\n"
    items_array = Array.new
    #@targets_names.each do |elem|
      #items_array.push([rand(9999), elem, 1 , "Enabled"])
    #end
    return items_array
  end

  def header
    [_("LUN"), _("Name"), _("path")]
  end

  def items
    @luns = generate_items()
    return @luns
  end

  def get_selected
    return self.value
  end

  #This function will return the array @luns, LUNsTableWidget will use this to decide the lun number
  def get_luns
    return @luns
  end

  #This function will return the array @luns_added, means the new luns need to create
  def get_new_luns
    return @luns_added
  end
 #this function will add a lun in the table, the parameter item is an array
  def add_lun_item(item)
    @luns.push(item)
    @luns_added.push(item)
    self.update_table(@luns)
  end

  #this function will delete a LUN both in a target tpg#n/luns and /backstore/fileio or block via targetcli
  def delete_lun(lun_str)
  end
  #this function will remove a lun from the table, will try to delete it from @luns_added and @luns
  def table_remove_lun_item(id)
    @luns_added.delete_if{|item| item[0] == id}
    @luns.delete_if{|item| item[0] == id}
    self.update_table(@luns)
  end

  def validate
    puts "validate() in LUN_table is called."
    #p @luns_added
    #This loop will validate whether the lun is a block device or fileio, return false if others.
    @luns_added.each do |lun|
      case lun[4]
        when "characterSpecial"
          Yast::Popup.Error(_("The selected storage is a character file, LUNs can only be fileio or block devices."))
          self.table_remove_lun_item(lun[0])
          return false
          break
        when "link"
          Yast::Popup.Error(_("The selected storage is a link file, LUNs can only be fileio or block devices."))
          self.table_remove_lun_item(lun[0])
          return false
          break
        when "socket"
          Yast::Popup.Error(_("The selected storage is a socket file, LUNs can only be fileio or block devices."))
          self.table_remove_lun_item(lun[0])
          return false
          break
        when "unknown"
          Yast::Popup.Error(_("The selected file type is unknow, LUNs can only be fileio or block devices."))
          self.table_remove_lun_item(lun[0])
          return false
          break
      end
    end
    #This loop will validate whether the lun is already in use
    @luns_added.each do |lun|
      #puts "Loop in validate() function"
      #p lun
      if $back_stores.validate_backstore_exist(lun[2])
        #puts lun[2]
        #puts "Detected an exsisted storeage in use"
        err_msg = _("The selected backend storeage ") + lun[2] + _(" is already in use.")
        Yast::Popup.Error(err_msg)
        self.table_remove_lun_item(lun[0])
        return false
      end
    end
    return true
  end

  def create_luns_backstore(lun)
    cmd = "targetcli"
    if lun[4] == "file"
      p1 = "backstores/fileio create name=" + lun[3] + " file_or_dev=" + lun[2]
    end
    if lun[4] == "blockSpecial"
      p1 = "backstores/block create name=" + lun[3] + " dev=" + lun[2]
    end
    ret = Yast::Execute.locally(cmd, p1, stdout: :capture)
  end
  
  def store
    puts "store() in LUNTable is called."
    #Here we will create new luns in backstore/fileio or block
    @luns_added.each do |lun|
      printf("It will adda lun with path %s, with lun type %s", lun[2], lun[4])
      self.create_luns_backstore(lun)
    end
  end

  def update_table(luns)
    self.change_items(luns)
  end
end


class LUNsTableWidget < CWM::CustomWidget
  include Yast
  include Yast::I18n
  include Yast::UIShortcuts
  include Yast::Logger
  def initialize
    self.handle_all_events = true
    @lun_table = LUNTable.new("test")
  end

  def contents
    VBox(
       @lun_table,
       HBox(
         PushButton(Id(:add), _("Add")),
         PushButton(Id(:edit), _("Edit")),
         PushButton(Id(:delete), _("Delete"))
       )
  )
  end

#return an array of the paths of all luns need to be created
 def get_luns_to_create
   luns_to_create = Array.new
   new_luns = @lun_table.get_new_luns
   p new_luns
   new_luns.each do |lun|
     luns_to_create.push(lun[2])
   end  
 end
  def handle(event)
    puts event
    case event["ID"]
      when :add
        file = UI.AskForExistingFile("/", "", _("Select a file or device"))
          if file == nil
            puts "No file selected"
          else
            #p file
            #p File.ftype(file)
          end
          luns = @lun_table.get_luns()
          lun_number = rand(100)
          # lun path to lun name. Like /home/lszhu/target.raw ==> home_lszhu_target.raw
          lun_name = file[1,file.length].gsub(/\//,"_")
          @lun_table.add_lun_item([rand(9999), lun_number, file,lun_name, File.ftype(file)])
       	end
     nil
  end

  def help
    _("demo help")
  end
end



