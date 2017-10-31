#iqn_name or eui_name would be a MatchData, but target_name would be a string.
#iqn_name= nil
#eui_name= nil
#target_name = nil
#initiator_name =  nil

#class ACL_group is the acls group under a iSCSI entry

class Backstores
  def initialize()
    @backstore_path = nil
    @re_backstore_path = Regexp.new(/\/[\w\/\.]+\s/)
    #@re_backstore_name = Regexp.new(/\/[\w\/\.]+\s/)
    #@backstores_list should Hash.new if we need to store storage name like iscsi_sdb
    @backstores_list = Array.new
    #p @output
    self.analyze
  end

  def analyze
    @output = Yast::Execute.locally("targetcli", "backstores/ ls", stdout: :capture)
    @backstores_output = @output.split("\n")
    @backstores_output.each do |line|
      if @backstore_path = @re_backstore_path.match(line)
        @backstores_list.push(@backstore_path.to_s.strip)
      end
    end
    #p "In backstores"
    #p @backstores_list
  end

  def get_backstores_list
    return @backstores_list
  end

  #This function will return whether the backstore(path) already exsited
  def validate_backstore_exist(str)
    #puts "validate_backstore_exist() is called." 
    #puts "The backstores_list is"
    #puts @backstores_list
    @backstores_list.each do |backstore|
      #puts "in the loop"
      #puts backstore
      #puts str
      if backstore == str
        #found the path(str) already exsited in the backsotre list, return true if exist
        return true
      end
    end
    return false
  end
end
class ACL_group
  @initiator_rules_hash_list = nil
  @up_level_TPG = nil
  def initialize()
    #puts "initialized a acls group"
    @initiator_rules_hash_list = Hash.new
  end
  def store_rule(name)
    @initiator_rules_hash_list.store(name, ACL_rule.new(name))
  end
  def fetch_rule(name)	
    @initiator_rules_hash_list.fetch(name)
  end
end

#class ACL_rule is the acl rule for a specific initaitor
class ACL_rule
  @initiator_name = nil
  @userid = nil
  @password = nil
  @mutual_userid = nil
  @multual_password = nil
  @mapped_luns_hash_list = nil
  def initialize(name)
    @initiator_name =name
    @mapped_luns_hash_list = Hash.new
  end
  def store_userid(id)
    @userid = id
  end
  def fetch_userid()
    @userid
  end
  def store_password(password)
    @password = password
  end
  def fetch_password()
    @password
  end
  def store_mutual_userid(id)
    @mutual_userid = id
  end
  def fetch_mutual_userid()
    @mutual_userid
  end
  def store_mutual_password(password)
    @mutual_password = password
  end
  def fetch_mutual_password()
    @mutual_password
  end
  def store_mapped_lun(mapping_lun_number)
    @mapped_luns_hash_list.store(mapping_lun_number, Mapped_LUN.new(mapping_lun_number))
  end
  def fetch_mapped_lun(mapping_lun_number)
     @mapped_luns_hash_list.fetch(mapping_lun_number)
  end 
end

class Mapped_LUN
  @mapping_lun_number = nil
  @mapped_lun_number = nil

  def initialize(mapping_lun_num)
    @mapping_lun_number = mapping_lun_num
  end
  
  def store_mapping_lun_number(num)
    @mapping_lun_number = num
  end
  def store_mapped_lun_number(num)
    @mapped_lun_number = num
  end
  def fetch_mapping_lun_number()
    @mapping_lun_number
  end
  def fetch_mapped_lun_number()
    @mapped_lun_number
  end
end

class TPG
  @tpg_number = nil
  @acls_hash_list = nil
  @up_level_target = nil
  @luns_list = nil
  def initialize(number)
    #printf("Create a TPG with number %d.\n",number)
    @tpg_number = number
    @acls_hash_list = Hash.new
    @luns_list = Hash.new
  end
  def fetch_tpg_number()
    @tpg_number
  end
  #for now, we only have one acl group in a tpg, called "acls", so we only have one key-value pair
  #in the hash. The key is fixed "acls" in store and fetch. We have a paremeter acls_name 
  #in store_acl() and fetch_acl() for further update. 
  def store_acls(acls_name)
    @acls_hash_list.store("acls", ACL_group.new())
  end
  def fetch_acls(acls_name)
     @acls_hash_list.fetch("acls")
  end

  def fetch_lun(lun_num)
    @luns_list.fetch(lun_num)
  end

  def store_lun(lun_num, lun_name)
    @luns_list.store(lun_num, lun_name)
  end

  #This function will return a Hast list contain all luns in the TPG
  def get_luns()
    return @luns_list
  end

  def get_luns_array()
    luns = Array.new
    @luns_list.each do |key,value|
      luns.push(value)
    end
    return luns
  end
  
end

class Target
  @target_name=nil
  @tpg_hash_list=nil
  def initialize(name)
    #printf("Initializing a target, name is %s.\n",name)
    @target_name = name
    @tpg_hash_list = Hash.new
  end
  #Hash opertion to store a TPG
  def store_tpg(tpg_number)
    @tpg_hash_list.store(tpg_number, TPG.new(tpg_number))
  end
  #Hash operation to fetch a TPG
  def fetch_tpg(tpg_number)
     @tpg_hash_list.fetch(tpg_number)
  end

  #For now, Yast only support the case that only has one TPG, this function will return the only TPG,
  # if there are more than one TPG in the target, it will return the first one.
  def get_default_tpg()
    if @tpg_hash_list.empty? == true
      return nil
    else
      @tpg_hash_list.each do |key,value|
        return value
      end
    end

  end

  def fetch_target_name()
    @target_name
  end
end

class TargetList
  @target_hash_list = nil
  def print()
    @target_hash_list.each do |key, value|
     p value
    end
  end

#This function will return a array of target names
  def get_target_names()
    #p "get_target_names() called"
    target_names_array = Array.new
    @target_hash_list.each do |key, value|
      target_names_array.push(key)
      #p key
    end
    return target_names_array
  end
  
  def initialize()
    @target_hash_list = Hash.new
  end
  def store_target(target_name)
    @target_hash_list.store(target_name, Target.new(target_name))
  end
  def fetch_target(target_name)
     @target_hash_list.fetch(target_name)
  end

end

class TargetData

  def initialize()
    #puts "initialize a TargetData class"
    @re_iqn_target = Regexp.new(/iqn\.\d{4}\-\d{2}\.[\w\.:\-]+\s\.+\s\[TPGs:\s\d+\]/)
    @re_iqn_name = Regexp.new(/iqn\.\d{4}-\d{2}\.[\w\.:\-]+/)

    @re_eui_target = Regexp.new(/eui\.\w+\s\.+\s\[TPGs:\s\d+\]/)
    @re_eui_name = Regexp.new(/eui\.\w+/)

    @re_tpg = Regexp.new(/tpg\d+\s/)

    @re_acls_group = Regexp.new(/acls\s\.+\s\[ACLs\:\s\d+\]/)

    @re_acl_iqn_rule = Regexp.new(/iqn\.\d{4}\-\d{2}\.[\w\.:\-]+\s\.+\s\[[\w\-\s\,]*Mapped\sLUNs\:\s\d+\]/)
    @re_acl_eui_rule = Regexp.new(/eui\.\w+\s\.+\s\[[\w\-\s\,]*Mapped\sLUNs\:\s\d+\]/)
  
    #match a line like this:
    #mapped_lun1 .......................................................................... [lun2 fileio/iscsi_file1 (rw)]
    @re_mapped_lun_line = Regexp.new(/mapped_lun\d+\s\.+\s\[lun\d+\s/)

    # match the mapped lun like "mapped_lun1", we matched one more \s here to aovid bugs in configfs / targetcli mismatch, need to strip when use
    @re_mapping_lun = Regexp.new(/mapped_lun\d+\s/)

    #match the mapped lun, like "[lun2" in "[lun2 fileio/iscsi_file1 (rw)]", we matched one more \s to avoid bugs.
    @re_mapped_lun = Regexp.new(/\[lun\d+\s/)

    #match a line like "| | | | o- lun2 ...................... [fileio/iscsi_file1 (/home/lszhu/target1.raw) (default_tg_pt_gp)]"
    #or "o- lun0 .................................................................. [block/iscsi_sdb (/dev/sdb) (default_tg_pt_gp)]"
    @re_lun = Regexp.new(/\-\slun\d+\s\.+\s\[(fileio|block)\//)
    #match lun number like lun0, lun1, lun2....
    @re_lun_num = Regexp.new(/\-\slun\d+\s/)
    #match lun name like [fileio/iscsi_file1 or [block/iscsi_sdb
    @re_lun_name = Regexp.new(/\[(fileio|block)\/[\w\_\-\d]+\s/)
    #match lun patch like:(/home/lszhu/target1.raw) or (/dev/sdb)
    @re_lun_path = Regexp.new(/[(]\/(\w|\.|\/)+[)]/)

    #iqn_name or eui_name would be a MatchData, but target_name would be a string.
    @iqn_name= nil
    @eui_name= nil
    @target_name = nil
    @initiator_name =  nil

    #tgp_name would be a MatchData, but tgp_num should be a string.
    @tpg_name = nil
    @tpg_num = nil

    #the string for a mapping lun, like mapped_lun1
   @mapping_lun_name = nil
    #the string for a mapped lun, like "lun2" in "[lun2 fileio/iscsi_file1 (rw)]"
    @mapped_lun_name = nil

    #will store anything match our regexp
    @match = nil

    # A pointer points to the target in the list that we are handling.
    @current_target = nil
    # A pointer points to the tpg in the target that we are handling.
    @current_tpg = nil
    # A pointer points to the acls group
    @current_acls_group = nil
    #A pointer points to the acl rule for a specific initiator we are handling
    @current_acl_rule = nil

    # the command need to execute  and the result
    @cmd = nil
    @cmd_out = nil
    ##TODO: Need to add some error handling code here, like failed to start the service.
    #@target_outout = `targetcli ls`.split("\n") #This is an arrry now, so that we can analyze the lines one by one
    @targets_list = TargetList.new
    self.analyze
  end


  def analyze()
    #TODO: Need to add some error handling code here, like failed to start the service.
    @target_outout = `targetcli ls`.split("\n") #This is an arrry now, so that we can analyze the lines one by one
    @target_outout.each do |line|
      #handle iqn targets here.
      if @re_iqn_target.match(line)
         #puts line
         if @iqn_name = @re_iqn_name.match(line) 
           #puts iqn_name
           @target_name=@iqn_name.to_s
           @targets_list.store_target(@target_name)
           @current_target = @targets_list.fetch_target(@target_name)
         end
      end

      #handle eui targets here.
      if @re_eui_target.match(line)
         #puts line
         if @eui_name = @re_eui_name.match(line)
           #puts eui_name
           @target_name=@eui_name.to_s
           @targets_list.store_target(@target_name)
           @current_target = @targets_list.fetch_target(@target_name)
         end
      end

      #handle TPGs here.
      if @tpg_name = @re_tpg.match(line)
         #puts tpg_name.to_s.strip
         #find the tpg number
         @tpg_num = /\d+/.match(@tpg_name.to_s.strip)
         @current_target.store_tpg(@tpg_num.to_s.strip)
         @current_tpg = @current_target.fetch_tpg(@tpg_num.to_s.strip)
      end

      #handle ACLs group here
      if @re_acls_group.match(line)
         #puts line
         @current_tpg.store_acls("acls")
         @current_acls_group = @current_tpg.fetch_acls("acls")
      end
  
      #handle acl rules for an IQN initaitor here
      if @re_acl_iqn_rule.match(line)
        #puts line
        #handle_acl_rule(match)
        @initiator_name = @re_iqn_name.match(line).to_s
        #puts initiator_name
        @current_acls_group.store_rule(@initiator_name)
        @current_acl_rule = @current_acls_group.fetch_rule(@initiator_name)
        #get authentication information here.
        #get userid
        @cmd = "targetcli iscsi/" + @current_target.fetch_target_name() + "/tpg" + @current_tpg.fetch_tpg_number() + "/acls/" + @initiator_name + "/ get auth userid"
        @cmd_out = `#{@cmd}`
        @current_acl_rule.store_userid(@cmd_out[7 , @cmd.length])
        #puts current_acl_rule.fetch_userid()
        #get password
        @cmd = "targetcli iscsi/" + @current_target.fetch_target_name() + "/tpg" + @current_tpg.fetch_tpg_number() + "/acls/" + @initiator_name + "/ get auth password"
        @cmd_out = `#{@cmd}`
        @current_acl_rule.store_password(@cmd_out[9 , @cmd.length])
        #puts current_acl_rule.fetch_password()
        #get mutual_userid
        @cmd = "targetcli iscsi/" + @current_target.fetch_target_name() + "/tpg" + @current_tpg.fetch_tpg_number() + "/acls/" + @initiator_name + "/ get auth mutual_userid"
        @cmd_out = `#{@cmd}`
        @current_acl_rule.store_mutual_userid(@cmd_out[14 , @cmd.length])
        #puts current_acl_rule.fetch_mutual_userid()
        #get mutual_password
        @cmd = "targetcli iscsi/" + @current_target.fetch_target_name() + "/tpg" + @current_tpg.fetch_tpg_number() + "/acls/" + @initiator_name + "/ get auth mutual_password"
        @cmd_out = `#{@cmd}`
        @current_acl_rule.store_mutual_password(@cmd_out[16 , @cmd.length])
        #puts current_acl_rule.fetch_mutual_password()
      end
  
      #handle acl rules for an EUI initaitor here
      if @re_acl_eui_rule.match(line)
        #puts line
        #handle_acl_rule(match)
        @initiator_name = @re_eui_name.match(line).to_s
        #puts initiator_name	
        @current_acls_group.store_rule(@initiator_name)
        @current_acl_rule = @current_acls_group.fetch_rule(@initiator_name)
        #get authentication information here.
        #get userid
        @cmd = "targetcli iscsi/" + @current_target.fetch_target_name() + "/tpg" + @current_tpg.fetch_tpg_number() + "/acls/" + @initiator_name + "/ get auth userid"
        @cmd_out = `#{@cmd}`
        @current_acl_rule.store_userid(@cmd_out[7 , @cmd.length])
        #puts current_acl_rule.fetch_userid()
        #get password
        @cmd = "targetcli iscsi/" + @current_target.fetch_target_name() + "/tpg" + @current_tpg.fetch_tpg_number() + "/acls/" + @initiator_name + "/ get auth password"
        @cmd_out = `#{@cmd}`
        @current_acl_rule.store_password(@cmd_out[9 , @cmd.length])
        #puts current_acl_rule.fetch_password()
        #get mutual_userid
        @cmd = "targetcli iscsi/" + @current_target.fetch_target_name() + "/tpg" + @current_tpg.fetch_tpg_number() + "/acls/" + @initiator_name + "/ get auth mutual_userid"
        @cmd_out = `#{@cmd}`
        @current_acl_rule.store_mutual_userid(@cmd_out[14 , @cmd.length])
        #puts current_acl_rule.fetch_mutual_userid()
        #get mutual_password
        @cmd = "targetcli iscsi/" + @current_target.fetch_target_name() + "/tpg" + @current_tpg.fetch_tpg_number() + "/acls/" + @initiator_name + "/ get auth mutual_password"
        @cmd_out = `#{@cmd}`
        @current_acl_rule.store_mutual_password(@cmd_out[16 , @cmd.length])
        #puts current_acl_rule.fetch_mutual_password()
      end

      #handle mapped luns here
      if @re_mapped_lun_line.match(line)
        #puts line
        @mapping_lun_name = @re_mapping_lun.match(line).to_s.strip
        #puts @mapping_lun_name
        @mapped_lun_name = @re_mapped_lun.match(line).to_s.strip
        @mapped_lun_name.slice!("[")
        #puts @mapped_lun_name
        mapping_lun_num = @mapping_lun_name[10,@mapping_lun_name.length]
        @current_acl_rule.store_mapped_lun(mapping_lun_num)
        mapped_lun_num = @mapped_lun_name[3,@mapped_lun_name.length]
        @current_acl_rule.fetch_mapped_lun(mapping_lun_num).store_mapped_lun_number(mapped_lun_num)
      end

      #handle luns here
      if @re_lun.match(line)
        p line
        #lun_num is a string like lun0, lun1,lun2....
        lun_num_tmp = @re_lun_num.match(line).to_s
        lun_num = lun_num_tmp[2,lun_num_tmp.length]
        #puts lun_num
        #lun_name_tmp = @re_lun_name.match(line).to_s
        #lun_name_tmp = line[line.index("["),line.index("(")]
        #puts lun_name_tmp
        #lun_name = lun_name_tmp[lun_name_tmp.index("/") + 1,lun_name_tmp.length-2]
        lun_name_tmp = line[line.index("[")+1 .. line.index("(")-2]
        puts lun_name_tmp
        lun_name = lun_name_tmp[lun_name_tmp.index("/")+1 .. lun_name_tmp.length]
        #lun_num_int is a number like 1,3,57.
        lun_num_int = lun_num[3,lun_num.length]
        lun_path_tmp = @re_lun_path.match(line).to_s
        lun_path = lun_path_tmp[1,lun_path_tmp.length-2]
        @current_tpg.store_lun(lun_num,[rand(9999), lun_num_int, lun_name, lun_path, File.ftype(lun_path)])
      end
    
    end # end of @target_outout.each do |line|

  end # end of the function

  def print()
    @targets_list.print()
    #@targets_list.print_target_names()
  end

 #this function will return are created target names.
  def get_target_names_array()
    #puts "get_target_names_array() called."
    names = Array.new
    names = @targets_list.get_target_names()
    return names
  end

  #This function will return the Hash list target_list
  def get_target_list()
    list = @targets_list
    return list
  end
end
