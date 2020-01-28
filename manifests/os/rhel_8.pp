# @summary Manage hand selected CIS controls for Rhel 8
#
# This class manages specific controls from the CIS benchmark for Windows. The source used is "CIS Microsoft Windows Server 2019 RTM (Release 1809) Benchmark
# v1.0.1 - 11-22-2019"
#
# @example
#   include secteam::os::rhel_8
class secteam::os::rhel_8 (
  Boolean $firewall_enabled = true,
  String  $password_history = '50',
  String  $password_length = '15',
) {


  
}
