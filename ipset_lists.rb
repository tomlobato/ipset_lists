#!/usr/bin/env ruby

# Iptables example:

# ipset create br   hash:net family inet  2> /dev/null
# ipset create br6  hash:net family inet6 2> /dev/null
# ipset create aws  hash:net family inet  2> /dev/null
# ipset create aws6 hash:net family inet6 2> /dev/null

# update-ipset.rb br
# update-ipset.rb aws

# iptables  -I INPUT -p tcp --dport 53   -m set --match-set aws  src -j DROP
# ip6tables -I INPUT -p udp --dport 53   -m set --match-set aws6 src -j DROP
# iptables  -I INPUT -p tcp --dport 53 ! -m set --match-set br   src -j DROP
# ip6tables -I INPUT -p udp --dport 53 ! -m set --match-set br6  src -j DROP

# Refs:

# https://docs.aws.amazon.com/general/latest/gr/aws-ip-ranges.html
# http://www.ipdeny.com/ipblocks/
# https://www.ccnahub.com/linux/building-public-and-private-ipset-whitelists/

# TODO
# https://www.maxcdn.com/one/assets/ips.txt
# https://www.pingdom.com/rss/probe_servers.xml
# https://www.cloudflare.com/ips-v4
# https://support.cloudflare.com/hc/en-us/articles/200169166-How-do-I-whitelist-Cloudflare-s-IP-addresses-in-iptables-
# https://github.com/firehol/blocklist-ipsets
# https://github.com/martenson/disposable-email-domains
# https://github.com/trick77/ipset-blacklist
# https://github.com/stamparm/ipsum
# https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/LocationsOfEdgeServers.html

require 'net/http'
require 'tempfile'

class UpdateIpset
    def initialize name
        @name = name
        setup
        if reason = invalid?
            raise ArgumentError, "Invalid argument: #{reason}"
        end
    end

    def setup
    end

    def invalid?
        nil
    end

    def update
        fetch

        set4 = @name
        set6 = @name + '6'
        @set4_tmp = set4 + '_tmp'
        @set6_tmp = set6 + '_tmp'

        @cmd = []

        parse

        run "ipset create #{set4} hash:net family inet", ignore_errors: true
        run "ipset create #{set6} hash:net family inet6", ignore_errors: true
        run "ipset create #{@set4_tmp} hash:net family inet", ignore_errors: true
        run "ipset create #{@set6_tmp} hash:net family inet6", ignore_errors: true

        tmpfile do |file|
            @cmd.uniq.each{|c| file.write "#{c}\n" }
            run "ipset -f #{file.path} restore"
        end

        run "ipset -W #{set4} #{@set4_tmp}"
        run "ipset -W #{set6} #{@set6_tmp}"

        run "ipset -X #{@set4_tmp}"
        run "ipset -X #{@set6_tmp}"

        puts <<~MSG
            Created ipset #{@name} (#{@report})
            Iptables examples:
            iptables -I INPUT -p tcp -m multiport --dport 80,443,53 -m set --match-set #{@name} src -j DROP
            iptables -I INPUT -m set --match-set #{@name} src -j REJECT
        MSG
    end

    def run cmd, ignore_errors: false
        output = `#{cmd} 2>&1`
        if $?.exitstatus != 0 && !ignore_errors
            msg = <<~MSG
                Error running command '#{cmd}'
                status: #{$?.exitstatus}
                output: #{output}
            MSG
            raise RuntimeError, msg
        end
        output
    end

    def tmpfile
        file = Tempfile.new __FILE__
        yield file
        file.close
        file.unlink
    end
end

class UpdateIpsetAws < UpdateIpset
    def fetch
        require 'json'
        @nets = JSON.parse Net::HTTP.get(URI('https://ip-ranges.amazonaws.com/ip-ranges.json'))
    end

    def parse
        @cmd += @nets['prefixes'].map{ |p|
            "add #{@set4_tmp} " + p['ip_prefix']
        }
        @cmd += @nets['ipv6_prefixes'].map{ |p|
            "add #{@set6_tmp} " + p['ipv6_prefix']
        }
        @report = "ipv4: #{@nets['prefixes'].size}, ipv6: #{@nets['ipv6_prefixes'].size}"
    end
end

class UpdateIpsetCountry < UpdateIpset
    # http://www.ipdeny.com/ipblocks/
    COUNTRY_CODES = %w(ad ae af ag ai al am ao ap ar as at au aw ax az ba bb bd be bf bg bh bi bj bl bm bn bo bq br bs bt bw by bz ca cd cf cg ch ci ck cl cm cn co cr cu cv cw cy cz de dj dk dm do dz ec ee eg er es et eu fi fj fk fm fo fr ga gb gd ge gf gg gh gi gl gm gn gp gq gr gt gu gw gy hk hn hr ht hu id ie il im in io iq ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mf mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg si sk sl sm sn so sr ss st sv sx sy sz tc td tg th tj tk tl tm tn to tr tt tv tw tz ua ug um us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw) 

    def setup
        if @name =~ /^country_(.*)/
            @country_code = $1
        else
            raise ArgumentError, "Invalid name #{@name}"
        end
    end
    
    def fetch
        @net4 = Net::HTTP.get(URI("http://www.ipdeny.com/ipblocks/data/aggregated/#{@country_code}-aggregated.zone")).split "\n"
        @net6 = Net::HTTP.get(URI("http://www.ipdeny.com/ipv6/ipaddresses/blocks/#{@country_code}.zone")).split "\n"
    end

    def parse
        @cmd += @net4.map{|p| "add #{@set4_tmp} " + p}
        @cmd += @net6.map{|p| "add #{@set6_tmp} " + p}
        @report = "ipv4: #{@net4.size}, ipv6: #{@net6.size}"
    end

    def invalid?
        unless COUNTRY_CODES.include? @country_code
            <<~REASON
                Unknown country code '#{@country_code}'.
                Allowed list:
                #{COUNTRY_CODES.join ' '}
            REASON
        end
    end
end

case ARGV[0]
when /^country_..$/
    UpdateIpsetCountry.new(ARGV[0]).update
when 'aws'
    UpdateIpsetAws.new(ARGV[0]).update
else
    raise ArgumentError, "#{__FILE__} country_<cc>|aws\n See http://www.ipdeny.com/ipblocks/ for the list of country codes."  
end
