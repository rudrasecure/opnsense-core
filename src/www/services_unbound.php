<?php

/*
 * Copyright (C) 2018-2021 Franco Fichtner <franco@opnsense.org>
 * Copyright (C) 2018 Fabian Franz
 * Copyright (C) 2014-2016 Deciso B.V.
 * Copyright (C) 2014 Warren Baker <warren@decoy.co.za>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

require_once("guiconfig.inc");
require_once("system.inc");
require_once("interfaces.inc");
require_once("plugins.inc.d/unbound.inc");

$a_unboundcfg = &config_read_array('unbound');

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $pconfig = array();
    // boolean values
    $pconfig['enable'] = isset($a_unboundcfg['enable']);
    $pconfig['enable_wpad'] = isset($a_unboundcfg['enable_wpad']);
    $pconfig['dnssec'] = isset($a_unboundcfg['dnssec']);
    $pconfig['dns64'] = isset($a_unboundcfg['dns64']);
    $pconfig['noarecords'] = isset($a_unboundcfg['noarecords']);
    $pconfig['reglladdr6'] = empty($a_unboundcfg['noreglladdr6']);
    $pconfig['regdhcp'] = isset($a_unboundcfg['regdhcp']);
    $pconfig['regdhcpstatic'] = isset($a_unboundcfg['regdhcpstatic']);
    $pconfig['txtsupport'] = isset($a_unboundcfg['txtsupport']);
    $pconfig['cacheflush'] = isset($a_unboundcfg['cacheflush']);
    $pconfig['noregrecords'] = isset($a_unboundcfg['noregrecords']);
    // text values
    $pconfig['port'] = !empty($a_unboundcfg['port']) ? $a_unboundcfg['port'] : null;
    $pconfig['regdhcpdomain'] = !empty($a_unboundcfg['regdhcpdomain']) ? $a_unboundcfg['regdhcpdomain'] : null;
    $pconfig['dns64prefix'] = !empty($a_unboundcfg['dns64prefix']) ? $a_unboundcfg['dns64prefix'] : null;
    // array types
    $pconfig['active_interface'] = !empty($a_unboundcfg['active_interface']) ? explode(",", $a_unboundcfg['active_interface']) : array();
    $pconfig['outgoing_interface'] = !empty($a_unboundcfg['outgoing_interface']) ? explode(",", $a_unboundcfg['outgoing_interface']) : array();
    $pconfig['local_zone_type'] = !empty($a_unboundcfg['local_zone_type']) ? $a_unboundcfg['local_zone_type'] : null;
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input_errors = array();
    $pconfig = $_POST;

    if (!empty($pconfig['apply'])) {
        system_resolver_configure();
        unbound_configure_do();
        plugins_configure('dhcp');
        clear_subsystem_dirty('unbound');
        header(url_safe('Location: /services_unbound.php'));
        exit;
    } else {
        // perform validations
        $unbound_port = empty($pconfig['port']) ? "53" : $pconfig['port'];
        $port_conflict = service_by_filter(['dns_ports' => $unbound_port]);
        if (isset($pconfig['enable']) && !empty($port_conflict) && $port_conflict['name'] != 'unbound') {
            $input_errors[] = sprintf(gettext('%s is currently using this port.'), $port_conflict['description']);
        }
        if (!empty($pconfig['regdhcpdomain']) && !is_domain($pconfig['regdhcpdomain'])) {
            $input_errors[] = gettext("The domain may only contain the characters a-z, 0-9, '-' and '.'.");
        }
        if (!empty($pconfig['dns64prefix']) && !is_subnetv6($pconfig['dns64prefix'])) {
            $input_errors[] = gettext("You must specify a valid DNS64 prefix.");
        }
        if (!empty($pconfig['port']) && !is_port($pconfig['port'])) {
            $input_errors[] = gettext("You must specify a valid port number.");
        }
        if (!empty($pconfig['local_zone_type']) && !array_key_exists($pconfig['local_zone_type'], unbound_local_zone_types())) {
            $input_errors[] = sprintf(gettext('Local zone type "%s" is not known.'), $pconfig['local_zone_type']);
        }

        if (count($input_errors) == 0) {
            // text types
            if (!empty($pconfig['port'])) {
                $a_unboundcfg['port'] = $pconfig['port'];
            } elseif  (isset($a_unboundcfg['port'])) {
                unset($a_unboundcfg['port']);
            }
            if (!empty($pconfig['regdhcpdomain'])) {
                $a_unboundcfg['regdhcpdomain'] = $pconfig['regdhcpdomain'];
            } elseif (isset($a_unboundcfg['regdhcpdomain'])) {
                unset($a_unboundcfg['regdhcpdomain']);
            }
            if (!empty($pconfig['dns64prefix'])) {
                $a_unboundcfg['dns64prefix'] = $pconfig['dns64prefix'];
            } elseif (isset($a_unboundcfg['dns64prefix'])) {
                unset($a_unboundcfg['dns64prefix']);
            }
            if (!empty($pconfig['local_zone_type'])) {
                $a_unboundcfg['local_zone_type'] = $pconfig['local_zone_type'];
            } elseif (isset($a_unboundcfg['local_zone_type'])) {
                unset($a_unboundcfg['local_zone_type']);
            }

            // boolean values
            $a_unboundcfg['noregrecords'] = !empty($pconfig['noregrecords']);
            $a_unboundcfg['cacheflush'] = !empty($pconfig['cacheflush']);
            $a_unboundcfg['dns64'] = !empty($pconfig['dns64']);
            $a_unboundcfg['noarecords'] = !empty($pconfig['noarecords']);
            $a_unboundcfg['dnssec'] = !empty($pconfig['dnssec']);
            $a_unboundcfg['enable'] = !empty($pconfig['enable']);
            $a_unboundcfg['enable_wpad'] = !empty($pconfig['enable_wpad']);
            $a_unboundcfg['noreglladdr6'] = empty($pconfig['reglladdr6']);
            $a_unboundcfg['regdhcp'] = !empty($pconfig['regdhcp']);
            $a_unboundcfg['regdhcpstatic'] = !empty($pconfig['regdhcpstatic']);
            $a_unboundcfg['txtsupport'] = !empty($pconfig['txtsupport']);

            // array types
            if (!empty($pconfig['active_interface'])) {
                $a_unboundcfg['active_interface'] = implode(',', $pconfig['active_interface']);
            } elseif (isset($a_unboundcfg['active_interface'])) {
                unset($a_unboundcfg['active_interface']);
            }
            if (!empty($pconfig['outgoing_interface'])) {
                $a_unboundcfg['outgoing_interface'] = implode(',', $pconfig['outgoing_interface']);
            } elseif (isset($a_unboundcfg['outgoing_interface'])) {
                unset($a_unboundcfg['outgoing_interface']);
            }

            write_config('Unbound general configuration changed.');
            mark_subsystem_dirty('unbound');
            header(url_safe('Location: /services_unbound.php'));
            exit;
        }
    }
}

$interfaces = get_configured_interface_with_descr();

foreach (array('server', 'client') as $mode) {
    foreach (config_read_array('openvpn', "openvpn-{$mode}") as $id => $setting) {
        if (!isset($setting['disable'])) {
            $interfaces['ovpn' . substr($mode, 0, 1) . $setting['vpnid']] =
                "OpenVPN {$mode} (" . (!empty($setting['description']) ?
                $setting['description'] : $setting['vpnid']) . ")";
        }
    }
}

legacy_html_escape_form_data($pconfig);

$service_hook = 'unbound';

include_once("head.inc");

?>
<body>
<script>
    $( document ).ready(function() {
        $("#show_advanced_dns").click(function (event) {
            event.preventDefault();
            $(this).parent().parent().hide();
            $(".showadv").show();
            $(window).trigger('resize');
        });
        // show advanced when option set
        if ($("#outgoing_interface").val() != '' || $("#enable_wpad").prop('checked')) {
            $("#show_advanced_dns").click();
        }
    });
</script>
<?php include("fbegin.inc"); ?>
  <section class="page-content-main">
    <div class="container-fluid">
      <div class="row">
        <?php if (isset($input_errors) && count($input_errors) > 0) print_input_errors($input_errors); ?>
        <?php if (is_subsystem_dirty('unbound')): ?><br/>
        <?php print_info_box_apply(gettext('The Unbound configuration has been changed.') . ' ' . gettext('You must apply the changes in order for them to take effect.')) ?>
        <?php endif; ?>
        <form method="post" name="iform" id="iform">
          <section class="col-xs-12">
            <div class="tab-content content-box col-xs-12">
                <div class="table-responsive">
                  <table class="table table-striped opnsense_standard_table_form">
                    <tbody>
                      <tr>
                        <td style="width:22%"><strong><?= gettext('General options') ?></strong></td>
                        <td style="width:78%; text-align:right">
                          <small><?=gettext("full help"); ?> </small>
                          <i class="fa fa-toggle-off text-danger"  style="cursor: pointer;" id="show_all_help_page"></i>
                        </td>
                      </tr>
                      <tr>
                        <td><i class="fa fa-info-circle text-muted"></i> <?=gettext("Enable");?></td>
                        <td>
                          <input name="enable" type="checkbox" value="yes" <?=!empty($pconfig['enable']) ? 'checked="checked"' : '';?> />
                          <?= gettext('Enable Unbound') ?>
                        </td>
                      </tr>
                      <tr>
                        <td><a id="help_for_port" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> <?=gettext("Listen Port");?></td>
                        <td>
                            <input name="port" type="text" id="port" placeholder="53" size="6" value="<?=$pconfig['port'];?>" />
                            <div class="hidden" data-for="help_for_port">
                                <?=gettext("The port used for responding to DNS queries. It should normally be left blank unless another service needs to bind to TCP/UDP port 53.");?>
                            </div>
                        </td>
                      </tr>
                      <tr>
                        <td><a id="help_for_active_interface" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> <?=gettext("Network Interfaces"); ?></td>
                        <td>
                          <select name="active_interface[]" multiple="multiple" class="selectpicker" title="<?= html_safe(gettext('All (recommended)')) ?>">
<?php foreach ($interfaces as $ifname => $ifdescr): ?>
                            <option value="<?= html_safe($ifname) ?>" <?=!empty($pconfig['active_interface'][0]) && in_array($ifname, $pconfig['active_interface']) ? 'selected="selected"' : '' ?>><?= html_safe($ifdescr) ?></option>
<?php endforeach ?>
                          </select>
                          <div class="hidden" data-for="help_for_active_interface">
                            <?=gettext("Interface IP addresses used for responding to queries from clients. If an interface has both IPv4 and IPv6 IPs, both are used. Queries to other interface IPs not selected below are discarded. The default behavior is to respond to queries on every available IPv4 and IPv6 address.");?>
                          </div>
                        </td>
                      </tr>
                      <tr>
                        <td><i class="fa fa-info-circle text-muted"></i> <?=gettext("DNSSEC");?></td>
                        <td>
                          <input name="dnssec" type="checkbox" value="yes" <?=!empty($pconfig['dnssec']) ? 'checked="checked"' : '';?> />
                          <?= gettext('Enable DNSSEC Support') ?>
                        </td>
                      </tr>
                      <tr>
                        <td><a id="help_for_dns64" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> <?=gettext("DNS64");?></td>
                        <td>
                          <input name="dns64" type="checkbox" id="dns64" value="yes" <?=!empty($pconfig['dns64']) ? 'checked="checked"' : '';?> />
                          <?= gettext('Enable DNS64 Support') ?>
                          <div class="hidden" data-for="help_for_dns64">
                            <?= gettext("If this option is set, Unbound will synthesize AAAA " .
                            "records from A records if no actual AAAA records are present."); ?>
                          </div>
                          <input placeholder="<?=gettext("DNS64 prefix");?>" title="<?=gettext("DNS64 prefix");?>" name="dns64prefix" type="text" id="dns64prefix" value="<?= $pconfig['dns64prefix'] ?>" />
                          <div class="hidden" data-for="help_for_dns64">
                            <?= gettext("If no DNS64 prefix is specified, the default prefix " .
                            "64:ff9b::/96 (RFC 6052) will be used."); ?>
                          </div>
                          <input name="noarecords" type="checkbox" id="noarecords" value="yes" <?=!empty($pconfig['noarecords']) ? 'checked="checked"' : '';?> />
                          <?= gettext('Enable AAAA-only mode') ?>
                          <div class="hidden" data-for="help_for_dns64">
                            <?= gettext("If this option is set, Unbound will remove all A " .
                            "records from the answer section of all responses."); ?>
                          </div>
                        </td>
                      </tr>
                      <tr>
                        <td><a id="help_for_regdhcp" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> <?=gettext("DHCP Registration");?></td>
                        <td>
                          <input name="regdhcp" type="checkbox" id="regdhcp" value="yes" <?=!empty($pconfig['regdhcp']) ? 'checked="checked"' : '';?> />
                          <?= gettext('Register DHCP leases') ?>
                          <div class="hidden" data-for="help_for_regdhcp">
                            <?= gettext("If this option is set, then machines that specify " .
                            "their hostname when requesting a DHCP lease will be registered " .
                            "in Unbound, so that their name can be resolved."); ?>
                          </div>
                        </td>
                      </tr>
                      <tr>
                        <td><a id="help_for_regdhcpdomain" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> <?=gettext("DHCP Domain Override");?></td>
                        <td>
                          <input name="regdhcpdomain" type="text" id="regdhcpdomain" value="<?= $pconfig['regdhcpdomain'] ?>"/>
                          <div class="hidden" data-for="help_for_regdhcpdomain">
                            <?= gettext("The default domain name to use for DHCP lease registration. If empty, the system domain is used.") ?>
                          </div>
                        </td>
                      </tr>
                      <tr>
                        <td><a id="help_for_regdhcpstatic" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> <?= gettext('DHCP Static Mappings');?></td>
                        <td>
                          <input name="regdhcpstatic" type="checkbox" id="regdhcpstatic" value="yes" <?=!empty($pconfig['regdhcpstatic']) ? 'checked="checked"' : '';?> />
                          <?= gettext('Register DHCP static mappings') ?>
                          <div class="hidden" data-for="help_for_regdhcpstatic">
                            <?= sprintf(gettext("If this option is set, then DHCP static mappings will ".
                                "be registered in Unbound, so that their name can be ".
                                "resolved. You should also set the domain in %s".
                                "System: General setup%s to the proper value."),'<a href="system_general.php">','</a>');?>
                          </div>
                        </td>
                      </tr>
                      <tr>
                        <td><a id="help_for_reglladdr6" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> <?= gettext('IPv6 Link-local') ?></td>
                        <td>
                          <input name="reglladdr6" type="checkbox" id="reglladdr6" value="yes" <?= !empty($pconfig['reglladdr6']) ? 'checked="checked"' : '' ?>/>
                          <?= gettext('Register IPv6 link-local addresses') ?>
                          <div class="hidden" data-for="help_for_reglladdr6">
                            <?= gettext("If this option is unset, then IPv6 link-local " .
                            "addresses will not be registered in Unbound, preventing " .
                            "return of unreachable address when more " .
                            "than one listen interface is configured."); ?>
                          </div>
                        </td>
                      </tr>
                      <tr>
                          <td><a id="help_for_noregrecords" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> <?= gettext('System A/AAAA records') ?></td>
                          <td>
                              <input name="noregrecords" type="checkbox" id="noregrecords" value="yes" <?= !empty($pconfig['noregrecords']) ? 'checked="checked"' : '' ?>/>
                              <?= gettext('Do not register system A/AAAA records') ?>
                              <div class="hidden" data-for="help_for_noregrecords">
                                  <?= sprintf(gettext("If this option is set, then no A/AAAA records for " .
                                  "the configured listen interfaces will be generated. " .
                                  "If desired, you can manually add them in %sUnbound DNS: Overrides%s. " .
                                  "Use this to control which interface IP addresses are mapped to the system host/domain name " .
                                  "as well as to restrict the amount of information exposed in replies to queries for the system host/domain name ."), '<a href="ui/unbound/overrides/">', '</a>'); ?>
                              </div>
                          </td>
                      </tr>
                      <tr>
                        <td><a id="help_for_txtsupport" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> <?=gettext("TXT Comment Support");?></td>
                        <td>
                          <input name="txtsupport" type="checkbox" value="yes" <?=!empty($pconfig['txtsupport']) ? 'checked="checked"' : '';?> />
                          <?= gettext('Create corresponding TXT records') ?>
                          <div class="hidden" data-for="help_for_txtsupport">
                            <?=gettext("If this option is set, then any descriptions associated with Host entries and DHCP Static mappings will create a corresponding TXT record.");?>
                          </div>
                        </td>
                      </tr>
                      <tr>
                        <td><a id="help_for_cacheflush" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> <?=gettext('DNS Cache');?></td>
                        <td>
                          <input name="cacheflush" type="checkbox" value="yes" <?=!empty($pconfig['cacheflush']) ? 'checked="checked"' : '';?> />
                          <?= gettext('Flush DNS cache during reload') ?>
                          <div class="hidden" data-for="help_for_cacheflush">
                            <?= gettext('If this option is set, the DNS cache will be flushed during each daemon reload. This is the default behavior for Unbound, but may be undesired when multiple dynamic interfaces require frequent reloading.') ?>
                          </div>
                        </td>
                      </tr>
                      <tr>
                        <td><a id="help_for_local_zone_type" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> <?=gettext("Local Zone Type"); ?></td>
                        <td>
                          <select name="local_zone_type" size="3" class="selectpicker" >
<?php foreach (unbound_local_zone_types() as $value => $name): ?>
                            <option value="<?= html_safe($value) ?>" <?= $value == $pconfig['local_zone_type'] ? 'selected="selected"' : '' ?>><?= html_safe($name) ?></option>
<?php endforeach ?>
                          </select>
                          <div class="hidden" data-for="help_for_local_zone_type">
                            <?=sprintf(gettext('The local zone type used for the system domain. Type descriptions are available under "local-zone:" in the %sunbound.conf(5)%s manual page. The default is \'transparent\'.'), '<a target="_blank" href="https://nlnetlabs.nl/documentation/unbound/unbound.conf/#local-zone">', '</a>');?>
                          </div>
                        </td>
                      </tr>
                      <tr>
                        <td><i class="fa fa-info-circle text-muted"></i> <?=gettext("Advanced");?></td>
                        <td>
                          <button id="show_advanced_dns" class="btn btn-xs btn-default" value="yes"><?= gettext('Show advanced option') ?></button>
                        </td>
                      </tr>
                      <tr class="showadv" style="display:none">
                        <td><a id="help_for_outgoing_interface" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> <?=gettext("Outgoing Network Interfaces"); ?></td>
                        <td>
                          <select id="outgoing_interface" name="outgoing_interface[]" multiple="multiple" class="selectpicker" title="<?= html_safe(gettext('All (recommended)')) ?>">
<?php foreach ($interfaces as $ifname => $ifdescr): ?>
                            <option value="<?= html_safe($ifname) ?>" <?=!empty($pconfig['outgoing_interface'][0]) && in_array($ifname, $pconfig['outgoing_interface']) ? 'selected="selected"' : '' ?>>
                              <?= html_safe($ifdescr) ?>
                            </option>
<?php endforeach ?>
                          </select>
                          <div class="hidden" data-for="help_for_outgoing_interface">
                            <?=gettext("Utilize different network interfaces that Unbound will use to send queries to authoritative servers and receive their replies. By default all interfaces are used. Note that setting explicit outgoing interfaces only works when they are statically configured.");?>
                          </div>
                        </td>
                      </tr>
                      <tr class="showadv" style="display:none">
                        <td><a id="help_for_enable_wpad" href="#" class="showhelp"><i class="fa fa-info-circle"></i></a> <?=gettext("WPAD Records");?></td>
                        <td>
                          <input id="enable_wpad" name="enable_wpad" type="checkbox" value="yes" <?=!empty($pconfig['enable_wpad']) ? 'checked="checked"' : '';?> />
                          <div class="hidden" data-for="help_for_enable_wpad">
                            <?=gettext("If this option is set, CNAME records for the WPAD host of all configured domains will be automatically added as well as overrides for TXT records for domains. " .
                                       "This allows automatic proxy configuration in your network but you should not enable it if you are not using WPAD or if you want to configure it by yourself.");?><br />
                          </div>
                        </td>
                      </tr>
                      <tr>
                        <td></td>
                        <td>
                          <input name="submit" type="submit" class="btn btn-primary" value="<?=html_safe(gettext('Save')); ?>" />
                        </td>
                      </tr>
                      <tr>
                        <td colspan="2">
                          <?= gettext('If Unbound is enabled, the DHCP'.
                          ' service (if enabled) will automatically serve the LAN IP'.
                          ' address as a DNS server to DHCP clients so they will use'.
                          ' Unbound resolver.');?>
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>
          </section>
         </form>
      </div>
    </div>
  </section>
<?php include("foot.inc"); ?>
