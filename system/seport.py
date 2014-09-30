#!/usr/bin/python

# (c) 2014, Dan Keder <dan.keder@gmail.com>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
---
module: seport
short_description: Manages SELinux network port type definitions
description:
     - Manages SELinux network port type definitions.
version_added: "1.7.1"
options:
  port:
    description:
      - Port number
    required: true
    default: null
  proto:
    description:
      - Protocol for the specified port.
    required: true
    default: null
    choices: [ 'tcp', 'udp' ]
  setype:
    description:
      - SELinux type for the specified port.
    required: true
    default: null
  state:
    description:
      - Desired boolean value.
    required: true
    default: present
    choices: [ 'present', 'absent' ]
  reload:
    description:
      - Reload SELinux policy after commit.
    required: false
    default: yes
notes:
   - The changes are persistent across reboots
   - Not tested on any debian based system
requirements: [ 'libselinux-python', 'policycoreutils-python' ]
author: Dan Keder
'''

EXAMPLES = '''
# Allow Apache to listen on tcp port 8888
- seport: port=8888 proto=tcp setype=http_port_t state=present
# Allow sshd to listen on tcp port 8991
- seport: port=8991 proto=tcp setype=ssh_port_t state=present
'''

try:
    import selinux
    HAVE_SELINUX=True
except ImportError:
    HAVE_SELINUX=False

try:
    import seobject
    HAVE_SEOBJECT=True
except ImportError:
    HAVE_SEOBJECT=False


def semanage_port_add(module, port, proto, setype, do_reload, serange='s0', sestore=''):
    """ Add SELinux port type to the policy.

    :return: True if the policy was changed, otherwise False
    """
    try:
        seport = seobject.portRecords(sestore)
        if not module.check_mode:
            seport.set_reload(do_reload)
            seport.add(port, proto, serange, setype)

    except ValueError as e:
        if e.message == "Port {0}/{1} already defined".format(proto, port):
            return False
        else:
            module.fail_json(msg="%s: %s\n" % (e.__class__.__name__, str(e)))
    except IOError as e:
        module.fail_json(msg="%s: %s\n" % (e.__class__.__name__, str(e)))
    except KeyError as e:
        module.fail_json(msg="%s: %s\n" % (e.__class__.__name__, str(e)))
    except OSError as e:
        module.fail_json(msg="%s: %s\n" % (e.__class__.__name__, str(e)))
    except RuntimeError as e:
        module.fail_json(msg="%s: %s\n" % (e.__class__.__name__, str(e)))

    return True


def semanage_port_del(module, port, proto, do_reload, sestore=''):
    """ Add SELinux port type to the policy.

    :return: True if the policy was changed, otherwise False
    """
    try:
        seport = seobject.portRecords(sestore)
        if not module.check_mode:
            seport.set_reload(do_reload)
            seport.delete(port, proto)

    except ValueError as e:
        if e.message == "Port {0}/{1} is not defined".format(proto, port):
            return False
        else:
            module.fail_json(msg="%s: %s\n" % (e.__class__.__name__, str(e)))
    except IOError as e:
        module.fail_json(msg="%s: %s\n" % (e.__class__.__name__, str(e)))
    except KeyError as e:
        module.fail_json(msg="%s: %s\n" % (e.__class__.__name__, str(e)))
    except OSError as e:
        module.fail_json(msg="%s: %s\n" % (e.__class__.__name__, str(e)))
    except RuntimeError as e:
        module.fail_json(msg="%s: %s\n" % (e.__class__.__name__, str(e)))

    return True


def main():
    module = AnsibleModule(
        argument_spec={
                'port': {
                    'required': True,
                },
                'proto': {
                    'required': True,
                    'choices': ['tcp', 'udp'],
                },
                'setype': {
                    'required': True,
                },
                'state': {
                    'required': True,
                    'choices': ['present', 'absent'],
                },
                'reload': {
                    'required': False,
                    'type': 'bool',
                    'default': 'yes',
                },
            },
        supports_check_mode=True
    )
    if not HAVE_SELINUX:
        module.fail_json(msg="This module requires libselinux-python")

    if not HAVE_SEOBJECT:
        module.fail_json(msg="This module requires policycoreutils-python")

    if not selinux.is_selinux_enabled():
        module.fail_json(msg="SELinux is disabled on this host.")

    port = module.params['port']
    proto = module.params['proto']
    setype = module.params['setype']
    state = module.params['state']
    do_reload = module.params['reload']

    result = {}
    result['port'] = port
    result['proto'] = proto
    result['setype'] = setype
    result['state'] = state

    if state == 'present':
        result['changed'] = semanage_port_add(module, port, proto, setype, do_reload)
    elif state == 'absent':
        result['changed'] = semanage_port_del(module, port, proto, do_reload)
    else:
        module.fail_json(msg='Invalid value of argument "state": {0}'.format(state))

    module.exit_json(**result)


from ansible.module_utils.basic import *
main()
