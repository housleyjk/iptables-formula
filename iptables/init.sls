# Firewall management module
{%- if salt['pillar.get']('firewall:enabled') %}
  {% set firewall = salt['pillar.get']('firewall', {}) %}
  {% set install = firewall.get('install', False) %}
  {% set strict_mode = firewall.get('strict', False) %}
  {% set global_block_nomatch = firewall.get('block_nomatch', False) %}
  # TODO: move to map.jinja
  {% set packages = salt['grains.filter_by']({
    'Debian': ['iptables', 'iptables-persistent'],
    'RedHat': ['iptables'],
    'default': 'Debian'}) %}

      {%- if install %}
      # Install required packages for firewalling      
      iptables_packages:
        pkg.installed:
          - names:
            {%- for pkg in packages %}
            - {{pkg}}
            {%- endfor %}
      {%- endif %}

    {%- if strict_mode %}
      # If the firewall is set to strict mode, we'll need to allow some 
      # that always need access to anything
      iptables_allow_localhost:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - source: 127.0.0.1
          - save: True

      # Allow related/established sessions
      iptables_allow_established:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - match: conntrack
          - ctstate: 'RELATED,ESTABLISHED'
          - save: True            

      # Set the policy to deny everything unless defined
      enable_reject_policy:
        iptables.set_policy:
          - table: filter
          - chain: INPUT
          - policy: REJECT
          - require:
            - iptables: iptables_allow_localhost
            - iptables: iptables_allow_established
    {%- endif %}

  # Generate ipsets for all services that we have information about
  {%- for service_name, service_details in firewall.get('services', {}).items() %}  
    {% set block_nomatch = service_details.get('block_nomatch', False) %}
    {% set invert_allow_all = service_details.get('allow_all', False) %}

    # Allow rules for ips/subnets
    {%- for ip in service_details.get('ips', invert_allow_all or ['0.0.0.0/0']) %}
      iptables_{{service_name}}_allow_{{ip}}:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - source: {{ip}}
          - dport: {{service_name}}
          - proto: tcp
          - comment: {{service_name}}_allow_{{ip}}
          - match: comment
          - save: True
    {%- endfor %}


    {%- if not strict_mode and global_block_nomatch or block_nomatch %}
      # If strict mode is disabled we may want to block anything else
      iptables_{{service_name}}_deny_other:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: REJECT
          - dport: {{ service_name }}
          - proto: tcp
          - save: True
    {%- endif %}    

  {%- endfor %}
{%- endif %}
