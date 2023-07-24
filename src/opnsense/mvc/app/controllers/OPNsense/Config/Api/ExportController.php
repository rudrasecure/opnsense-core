<?php

/**
 *    Copyright (C) 2023 RUDRA Cybersecurity Pvt. Ltd.
 *
 *    All rights reserved.
 *
 *    Redistribution and use in source and binary forms, with or without
 *    modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *
 *    THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 *    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 *    AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 *    AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 *    OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *    POSSIBILITY OF SUCH DAMAGE.
 *
 */

namespace OPNsense\Config\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\TrafficShaper\Api\SettingsController;

class CustomSettingsController extends SettingsController {
    /**
     * Search traffic shaper pipes
     * @return array list of found pipes
     * @throws \ReflectionException when not bound to model
     */
    public function customSearchRulesAction()
    {
        return $this->searchBase(
            "rules.rule",
            array("enabled", "interface", "proto", "source_not","source", "destination_not",
                  "destination", "description", "origin", "sequence", "target", "src_port", "dst_port"),
            "sequence"
        );
    }
}

class ExportController extends ApiMutableModelControllerBase {
    protected static $internalModelName = 'filter';
    protected static $internalModelClass = 'OPNsense\Firewall\Filter';
    /**
     * Export all OPNsense configuration and present it in the response body
     */
    public function doAction() {
        $xml_string = file_get_contents('/conf/config.xml');
        $xml = new \SimpleXMLElement($xml_string);
        $rules = $this->searchBase(
            "rules.rule",
            array(
                "action","description","destination_net","destination_not","destination_port","direction",
                "enabled","gateway","interface","ipprotocol","log","protocol","quick","sequence","source_net",
                "source_not","source_port"
            ),
            "sequence"
        )["rows"];
        $settingsController = new CustomSettingsController();
        $trafficShaperPipes = $settingsController->searchPipesAction()["rows"];
        $trafficShaperRules = $settingsController->customSearchRulesAction()["rows"];
        $unboundDnsController = new \OPNsense\Unbound\Api\SettingsController();
        $unboundDnsSettings = $unboundDnsController->getAction()["unbound"]["dnsbl"]["type"];
        $unboundDnsResults = [];
        foreach ($unboundDnsSettings as $key => $value) {
            $unboundDnsResults[] = [
                "key" => $key,
                "value" => $value["value"],
                "selected" => $value["selected"],
            ];
        }
        $json = json_encode([
            "interfaces" => $xml->interfaces,
            "firewallRules" => $rules,
            "trafficShaperPipes" => $trafficShaperPipes,
            "trafficShaperRules" => $trafficShaperRules,
            "unboundDnsBlocklists" => $unboundDnsResults,
        ]);
        return $json;
    }
 }
