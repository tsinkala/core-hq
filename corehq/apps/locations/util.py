from corehq.apps.locations.models import Location, root_locations, CustomProperty

def load_locs_json(domain, selected_loc_id=None):
    """initialize a json location tree for drill-down controls on
    the client. tree is only partially initialized and branches
    will be filled in on the client via ajax.

    what is initialized:
    * all top level locs
    * if a 'selected' loc is provided, that loc and its complete
      ancestry
    """
    def loc_to_json(loc):
        return {
            'name': loc.name,
            'location_type': loc.location_type,
            'uuid': loc._id,
        }
    loc_json = [loc_to_json(loc) for loc in root_locations(domain)]

    # if a location is selected, we need to pre-populate its location hierarchy
    # so that the data is available client-side to pre-populate the drop-downs
    if selected_loc_id:
        selected = Location.get(selected_loc_id)
        lineage = list(Location.view('_all_docs', keys=selected.path, include_docs=True))

        parent = {'children': loc_json}
        for loc in lineage:
            # find existing entry in the json tree that corresponds to this loc
            this_loc = [k for k in parent['children'] if k['uuid'] == loc._id][0]
            this_loc['children'] = [loc_to_json(loc) for loc in loc.children]
            parent = this_loc

    return loc_json

def defined_location_types(domain):
    return [
        'block',
        'district',
        'outlet',
        'state',
        'village',
    ]
  
# hard-coded for now
def allowed_child_types(domain, parent):
    parent_type = parent.location_type if parent else None

    return {
        None: ['state'],
        'state': ['district'],
        'district': ['block'],
        'block': ['village', 'outlet'],
        'village': ['outlet'],
        'outlet': [],
     }[parent_type]

# hard-coded for now
def location_custom_properties(domain, loc_type):
    try:
        return {
            'outlet': [
                CustomProperty(
                    name='site_code',
                    label='SMS Code',
                    required=True,
                    unique='global',
                ),
                CustomProperty(
                    name='outlet_type',
                    datatype='Choice',
                    label='Outlet Type',
                    required=True,
                    choices={'mode': 'static', 'args': [
                            'CHC',
                            'PHC',
                            'SC',
                            'MBBS',
                            'Pediatrician',
                            'AYUSH',
                            'Medical Store / Chemist',
                            'RMP',
                            'Asha',
                            'AWW',
                            'NGO',
                            'CBO',
                            'SHG',
                            'Pan Store',
                            'General Store',
                            'Other',
                        ]},
                ),
                CustomProperty(
                    name='outlet_type_other',
                    label='Outlet Type (Other)',
                ),
                CustomProperty(
                    name='address',
                    label='Address',
                ),
                CustomProperty(
                    name='landmark',
                    label='Landmark',
                ),
                CustomProperty(
                    name='contact_name',
                    label='Contact Name',
                ),
                CustomProperty(
                    name='contact_phone',
                    label='Contact Phone',
                ),
            ],
            'village': [
                CustomProperty(
                    name='village_size',
                    datatype='Integer',
                    label='Village Size',
                ),
                CustomProperty(
                    name='village_class',
                    datatype='Choice',
                    label='Village Class',
                    choices={'mode': 'static', 'args': [
                            'Town',
                            'A',
                            'B',
                            'C',
                            'D',
                            'E',
                        ]},
                ),
            ],
        }[loc_type]
    except KeyError:
        return []

