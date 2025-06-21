import uuid
import json

AEGIS_ROOT = {
    "version": 1,
    "header": {
        "slots": None,
        "params": None
    },
    "db": {
        "version": 3,
        "entries": [
        ],
        "groups": [],
        "icons_optimized": True
    }
}

PREFIX_TRANSLATION = {
    'aws': 'Amazon Web Services',
}

GROUPS = {
    'amazon web services': 'cloud',
    'google': 'email',
    'protonmail': 'email',
    'gitlab': 'git',
    'github': 'git',
    'digitalocean': 'cloud',
}

class OTPC:

    def __init__(self, input_filename: str, output_filename: str):

        self.input_filename = input_filename
        self.output_filename = output_filename

        self.group_by_uuid = []
        self.group_by_name = {}
        self.build_groups()
        self.decrypted_token_data = None
        self.aegis_data = AEGIS_ROOT
        self.read_decrypted_tokens()

        for each_entry in self.decrypted_token_data['decrypted_authenticator_tokens']:
            self.aegis_data['db']['entries'].append(self.new_entry(each_entry))

        self.write_aegis_decrypted_import()


    def read_decrypted_tokens(self):
        with open(self.input_filename, 'r') as rdt:
            self.decrypted_token_data = json.load(rdt)

    def write_aegis_decrypted_import(self):
        with open(self.output_filename, 'w') as wapt:
            json.dump(self.aegis_data, wapt, indent=4)


    def build_groups(self):
        '''
        constructs list of groups dictionary and dictionary of { group_name: group_uuid}
        '''
        groupByUUID = []
        groupByKey = {}
        tempGroups = {}
        for each_group in set(GROUPS.values()):
            group_uuid = str(uuid.uuid4())
            groupByUUID.append(
                { "uuid": group_uuid,
                "name" : each_group }
            )
            tempGroups[each_group] = group_uuid

        for each_key in GROUPS:
            groupByKey[each_key] = [tempGroups[x] for x in tempGroups if x==each_key]
        self.group_by_uuid = groupByUUID
        self.group_by_name = groupByKey
        AEGIS_ROOT["db"]["groups"] = self.group_by_uuid


    def new_entry(self, decrypted_entry: dict) -> dict:

        name_list = decrypted_entry['name'].split(':')
        name = name_list[-1]
        
        issuer = decrypted_entry['issuer'] or name_list[0] if len(name_list)>1 else 'unknown'

        # in my case, I had a number of 'names' that looked like this: Google:email_account@gmail.com
        # I also noticed that 'account_type' was sometimes populated with data, but this looked much more inconsistent,
        #   so I decided to handle these as they came up
        
        l_issuer = issuer.lower()
        
        # get group to put the entry into, if there is a match
        # note: even though this appeared to generate correctly, it didn't import;
        #       so don't spend too much time configuring this, unless you plan to debug
        matchToGroup = self.group_by_name.get(l_issuer)

        note = []

        if len(name_list) >1:
            if (l_issuer != name_list[0].lower() and 
            l_issuer != PREFIX_TRANSLATION.get(name_list[0].lower()) ):
                note.append(f'prefix: {name_list[0]}')
        
        if decrypted_entry['logo']:
            note.append(f'logo: {decrypted_entry["logo"]}')

        # {
        #     "account_type": "authenticator",
        #     "name": "GitHub:emailaddy",
        #     "issuer": "GitHub",
        #     "decrypted_seed": "blahblahblah",
        #     "digits": 6,
        #     "logo": "GitHub",
        #     "unique_id": "imauniqueid"
        # },

        ret = {
            "type": "totp",
            "uuid": str(uuid.uuid4()),
            "name": name,
            "issuer": issuer,
            "note": '\n'.join(note),
            "favorite": False,
            "icon": None,
            "info": {
                "secret": decrypted_entry['decrypted_seed'],
                "algo": "SHA1", # I think this is the default for most TOTP
                "digits": decrypted_entry['digits'],
                "period": 30
            },
            "groups": matchToGroup or []
        }

        return ret


if __name__ == '__main__':

    OTPC('decrypted_tokens.json', 'aegis_plaintext_import.json')
