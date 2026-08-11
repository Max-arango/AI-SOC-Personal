use tracing::info;

pub async fn enrich(event: &mut sentinel_events::Event) {
    if event.source == "network" {
        if let Some(ref payload) = event.payload {
            if let sentinel_events::event::Payload::NetworkEvent(ref ne) = payload {
                if !ne.remote_addr.is_empty() {
                    let ip = ne.remote_addr.clone();

                    let (abuse_result, shodan_result, otx_result, greynoise_result) = tokio::join!(
                        async {
                            if sentinel_plugin_abuseipdb::enabled() {
                                sentinel_plugin_abuseipdb::check_ip(&ip).await
                            } else {
                                None
                            }
                        },
                        async {
                            if sentinel_plugin_shodan::enabled() {
                                sentinel_plugin_shodan::lookup_host(&ip).await
                            } else {
                                None
                            }
                        },
                        async {
                            if sentinel_plugin_otx::enabled() {
                                sentinel_plugin_otx::check_ip(&ip).await
                            } else {
                                None
                            }
                        },
                        async {
                            if sentinel_plugin_greynoise::enabled() {
                                sentinel_plugin_greynoise::check_ip(&ip).await
                            } else {
                                None
                            }
                        }
                    );

                    if let Some(report) = abuse_result {
                        if report.abuse_score > 50 {
                            event.risk_score = event.risk_score.saturating_add(30);
                            event.tags.push("threat_intel:abuseipdb:high".into());
                            info!(
                                "AbuseIPDB enrichment: {} +30 risk (abuse_score={})",
                                ip, report.abuse_score
                            );
                        } else if report.abuse_score > 25 {
                            event.risk_score = event.risk_score.saturating_add(15);
                            event.tags.push("threat_intel:abuseipdb:medium".into());
                        }
                        if report.total_reports > 10 {
                            event.tags.push(format!(
                                "threat_intel:abuseipdb:{}_reports",
                                report.total_reports
                            ));
                        }
                    }

                    if let Some(report) = shodan_result {
                        if report.risk_score > 50 {
                            event.risk_score = event.risk_score.saturating_add(25);
                            event.tags.push("threat_intel:shodan:high".into());
                            info!(
                                "Shodan enrichment: {} +25 risk (ports={}, vulns={})",
                                ip,
                                report.open_ports.len(),
                                report.vulnerabilities.len()
                            );
                        } else if report.risk_score > 25 {
                            event.risk_score = event.risk_score.saturating_add(10);
                            event.tags.push("threat_intel:shodan:medium".into());
                        }
                        if !report.vulnerabilities.is_empty() {
                            event.tags.push("threat_intel:shodan:cve".into());
                        }
                        if !report.open_ports.is_empty() {
                            event.tags.push(format!(
                                "threat_intel:shodan:{}_ports",
                                report.open_ports.len()
                            ));
                        }
                    }

                    if let Some(report) = otx_result {
                        if report.risk_score > 50 {
                            event.risk_score = event.risk_score.saturating_add(25);
                            event.tags.push("threat_intel:otx:high".into());
                        } else if report.risk_score > 25 {
                            event.risk_score = event.risk_score.saturating_add(10);
                            event.tags.push("threat_intel:otx:medium".into());
                        }
                        if report.pulse_count > 0 {
                            event
                                .tags
                                .push(format!("threat_intel:otx:{}_pulses", report.pulse_count));
                        }
                        if !report.malware_families.is_empty() {
                            event.tags.push("threat_intel:otx:malware".into());
                        }
                        info!(
                            "OTX enrichment: {} +{} risk (pulses={}, malware={:?})",
                            ip, report.risk_score, report.pulse_count, report.malware_families
                        );
                    }

                    if let Some(report) = greynoise_result {
                        if report.classification == "malicious" {
                            event.risk_score = event.risk_score.saturating_add(25);
                            event.tags.push("grey_noise:malicious".into());
                        } else if report.classification == "benign" {
                            event.risk_score = event.risk_score.saturating_sub(5);
                            event.tags.push("grey_noise:benign".into());
                        }
                        if !report.name.is_empty() {
                            event
                                .tags
                                .push(format!("grey_noise:{}", report.name.to_lowercase()));
                        }
                        info!("GreyNoise: {} → {} ({})", ip, report.classification, report.name);
                    }

                    if sentinel_plugin_geoip::enabled() {
                        let geo = sentinel_plugin_geoip::resolver().lookup(&ip);
                        if let Some(ref data) = geo {
                            if !data.country_code.is_empty() {
                                event
                                    .tags
                                    .push(format!("geoip:cc:{}", data.country_code.to_lowercase()));
                            }
                            if !data.city.is_empty() {
                                event.tags.push(format!(
                                    "geoip:city:{}",
                                    data.city.to_lowercase().replace(' ', "_")
                                ));
                            }
                            if !data.asn_org.is_empty() {
                                event.tags.push(format!(
                                    "geoip:asn:{}",
                                    data.asn_org.to_lowercase().replace(' ', "_")
                                ));
                            }
                            if data.is_anonymous {
                                event.risk_score = event.risk_score.saturating_add(10);
                                event.tags.push("geoip:anonymous".into());
                            }
                        }
                    }

                    if sentinel_plugin_ioc::enabled() {
                        let engine = sentinel_plugin_ioc::engine();
                        if let Some(risk) = engine.lookup_ip(&ip) {
                            event.risk_score = event.risk_score.saturating_add(risk / 3);
                            event.tags.push("ioc:ip_match".into());
                        }
                    }
                }
            }
        }
    }

    if sentinel_plugin_virustotal::enabled() {
        if let Some(ref proc) = event.process {
            if !proc.sha256.is_empty() {
                let hash = proc.sha256.clone();
                let vt_result = sentinel_plugin_virustotal::lookup_hash(&hash).await;
                if let Some(report) = vt_result {
                    let base_boost = (report.threat_ratio * 50.0) as u32;
                    event.risk_score = event.risk_score.saturating_add(base_boost);

                    if report.malicious > 0 {
                        event.tags.push(format!(
                            "threat_intel:virustotal:malicious_{}",
                            report.malicious
                        ));
                    }
                    if report.threat_ratio > 0.3 {
                        event.tags.push("threat_intel:virustotal:high".into());
                    }
                    info!(
                        "VirusTotal enrichment: {} +{} risk (malicious={}/{}, ratio={:.0}%)",
                        report.name,
                        base_boost,
                        report.malicious,
                        report.total,
                        report.threat_ratio * 100.0
                    );
                }
            }
        }
    }

    if event.source == "browser" {
        if let Some(ref payload) = event.payload {
            if let sentinel_events::event::Payload::BrowserEvent(ref be) = payload {
                if !be.url.is_empty() {
                    let url = be.url.clone();
                    let result = sentinel_plugin_urlhaus::check_url(&url).await;
                    if let Some(report) = result {
                        if report.is_malicious {
                            event.risk_score = event.risk_score.saturating_add(report.risk_score);
                            event.tags.push("threat_intel:urlhaus:malicious".into());
                            event.tags.push(format!(
                                "threat_intel:urlhaus:{}",
                                report.threat.replace(' ', "_")
                            ));
                            info!(
                                "URLhaus enrichment: {} +{} risk (threat={}, tags={:?})",
                                url, report.risk_score, report.threat, report.tags
                            );
                        }
                    }
                }
            }
        }
    }
}
