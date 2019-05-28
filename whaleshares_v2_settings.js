// ==UserScript==
// @name         Auto-Enable Whaleshares v2 Slider
// @namespace    https://whaleshares.io/@alexpmorris
// @version      0.01
// @description  Protects MANA against a disabled slider setting
// @author       @alexpmorris
// @match        https://whaleshares.io/*
// @grant        none
// ==/UserScript==

(function() {
    'use strict';

    var settings = localStorage.getItem('settings');
    if (settings == null) {
      // set default settings and enable slider at 25%

      var settingsObj = { locale: "en-US",
                          votingPower: "on",
                          votePercent: 2500,
                          showNSFWPosts: true,
                          rewriteLinks: false
                        };

      localStorage.setItem('settings', JSON.stringify(settingsObj));
      alert("Script: Set Default Whaleshares Settings and Enabled Slider!");
    }

})();
