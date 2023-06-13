import json
import sys

fop_types = {
    'file_operations': {'2', '3', '4', '5', '10', '12'}, # '11'
    'fb_ops': {'3', '4', '16', '17', '18'},
    'bin_attribute': {'3', '4', '5'},
    'driver_attribute': {'1', '2'},
    'device_attribute': {'1', '2'},
    'kobj_attribute': {'1', '2'},
    'configfs_attribute': {'3', '4'},
    'class_attribute': {'1', '2'},
    'slab_attribute': {'1', '2'},
    'netdev_queue_attribute': {'1', '2'},
    'rx_queue_attribute': {'1', '2'},
    'krinst_attribute': {'1', '2'},
    'ffsinst_attribute': {'1', '2'},
    'bg_iostat_attr': {'1', '2'},
    'dhd_attr': {'1', '2'},
    'f2fs_attr': {'1', '2'},
    'ontime_attr': {'1', '2'},
    'queue_sysfs_entry': {'1', '2'},
    'sysfs_ops': {'0', '1'},
    'governor_attr': {'1', '2'},
    'netlink_kernel_cfg': {'2'},
    'genl_ops': {'0'},
    'wiphy_vendor_command': {'2'},
    'tsp_cmd': {'2'},
    'kernel_param_ops': {'1', '2'},
    'v4l2_ioctl_ops': {},
    'v4l2_subdev_core_ops': {'6'},
    # additional:
    'proc_ops': {'3', '4', '5', '9', '11'},
    'kernfs_ops': {'2', '6', '9', '11'},
    'cftype': {'10', '11', '12', '16', '17', '18'},
}

if len(sys.argv) < 2:
    print("Usage: %s <db.json>" % sys.argv[0], file=sys.stderr)
    sys.exit(1)

with open(sys.argv[1], "r") as dbjson_file:
    db = json.load(dbjson_file)

    id_to_funcname = dict()
    all_fops = set()
    unknown_ids = set()

    for func in db['funcs']:
        id_to_funcname[func['id']] = func['name']

    for fop in db['fops']['vars']:
        fop_type = fop['type']
        members = fop['members']
        if fop_type in fop_types:
            for (idx, func_idx) in members.items():
                if len(fop_types[fop_type]) > 0 and not idx in fop_types[fop_type]:
                    continue

                if func_idx in id_to_funcname:
                    all_fops.add(id_to_funcname[func_idx])
                    #print(id_to_funcname[func_idx])
                elif func_idx not in unknown_ids:
                    print("No func with id: %s" % func_idx, file=sys.stderr)
                    unknown_ids.add(func_idx)

    for func in all_fops:
        print(func)

