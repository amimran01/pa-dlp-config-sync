import requests
from requests.auth import HTTPBasicAuth
import json
import yaml
import argparse
from typing import List, Dict, Tuple
from deepdiff import DeepDiff
from pathlib import Path

class PrismaAccessSync:
    """DLP configuration synchronization tool between Prisma Access tenants"""

    # Metadata fields to exclude from comparison
    METADATA_FIELDS = {
        'id', 'created_at', 'created_by', 'updated_at', 
        'updated_by', 'version', 'tenant', 'tenant_id'
    }
    
    def __init__(self, source_creds: Dict, dest_creds_list: List[Dict]):
        """
        Initialize connections to source environment and destinations

        Args:
            source_creds: {'service_account': '...', 'api_key': '...', 'scope': '...', 'name': 'Source'}
            dest_creds_list: List of dicts [{'service_account': '...', 'api_key': '...', 'scope': '...', 'name': 'Prod'}, ...]
        """
        self.source_creds = source_creds
        self.source_token = self._authenticate(source_creds)

        # Authenticate all destination tenants
        self.destinations = []
        for dest_creds in dest_creds_list:
            try:
                token = self._authenticate(dest_creds)
                self.destinations.append({
                    'name': dest_creds.get('name', f"Tenant {len(self.destinations) + 1}"),
                    'token': token,
                    'creds': dest_creds
                })
                print(f"✅ Connection successful: {self.destinations[-1]['name']}")
            except Exception as e:
                print(f"❌ Connection error {dest_creds.get('name', 'tenant')}: {str(e)}")
        
        self.data_pattern_url = "https://api.dlp.paloaltonetworks.com/v1/api/data-pattern"
        self.data_profile_url = "https://api.dlp.paloaltonetworks.com/v1/api/data-profile"
        print(f"\n📊 {len(self.destinations)} destination tenant(s) connected\n")
        
    def _authenticate(self, creds: Dict) -> str:
        """Authenticates and retrieves access token"""
        auth_url = "https://auth.apps.paloaltonetworks.com/auth/v1/oauth2/access_token"
        
        data = {
            "grant_type": "client_credentials",
            "scope": creds['scope']
        }
        
        response = requests.post(
            auth_url,
            data=data,
            auth=HTTPBasicAuth(creds['service_account'], creds['api_key']),
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        
        if response.status_code != 200:
            raise Exception(f"Authentication error: {response.status_code} - {response.text}")
        
        return response.json().get("access_token")
    
    def _get_headers(self, token: str) -> Dict:
        """Returns headers for API calls"""
        return {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "client-name": "dlp-micro-app",
            "service-name": "dlp-micro-app"
        }
    
    def get_data_patterns(self, token: str, custom_only: bool = True) -> List[Dict]:
        """
        Retrieves data patterns from a tenant

        Args:
            token: Authentication token
            custom_only: If True, returns only custom patterns (non-predefined)
        """
        response = requests.get(
            self.data_pattern_url,
            headers=self._get_headers(token)
        )
        
        if response.status_code != 200:
            raise Exception(f"Error during retrieval: {response.status_code} - {response.text}")
        
        patterns = response.json().get("resources", [])
        
        if custom_only:
            patterns = [p for p in patterns if p.get("type") != "predefined"]
        
        return patterns
    
    def get_data_profiles(self, token: str, custom_only: bool = True) -> List[Dict]:
        """
        Retrieves data profiles from a tenant

        Args:
            token: Authentication token
            custom_only: If True, returns only custom profiles (non-predefined)
        """
        response = requests.get(
            self.data_profile_url,
            headers=self._get_headers(token)
        )
        
        if response.status_code != 200:
            raise Exception(f"Error retrieving profiles: {response.status_code} - {response.text}")

        profiles = response.json()

        # The API returns a list directly for profiles
        if not isinstance(profiles, list):
            profiles = profiles.get("resources", [])
        
        if custom_only:
            profiles = [p for p in profiles if p.get("profile_type") == "custom"]
        
        return profiles
    
    def _normalize_pattern(self, pattern: Dict) -> Dict:
        """
        Normalizes a pattern by removing metadata

        Args:
            pattern: Complete pattern

        Returns:
            Pattern without metadata
        """
        return {k: v for k, v in pattern.items() if k not in self.METADATA_FIELDS}
    
    def _remap_pattern_ids(self, profile: Dict, pattern_id_mapping: Dict[str, str]) -> Dict:
        """
        Replaces pattern IDs in a profile with destination IDs

        Args:
            profile: Profile containing references to patterns
            pattern_id_mapping: Mapping source_ID -> destination_ID

        Returns:
            Profile with remapped IDs
        """
        import copy
        profile = copy.deepcopy(profile)

        # Remap IDs in advance_data_patterns_rules
        if profile.get('advance_data_patterns_rules'):
            for rule in profile['advance_data_patterns_rules']:
                if rule.get('conditions'):
                    for condition in rule['conditions']:
                        if condition.get('rule_items'):
                            for rule_item in condition['rule_items']:
                                if rule_item.get('id') in pattern_id_mapping:
                                    rule_item['id'] = pattern_id_mapping[rule_item['id']]

        # Remap IDs in detection_rules
        if profile.get('detection_rules'):
            for detection_rule in profile['detection_rules']:
                if detection_rule.get('expression_tree'):
                    self._remap_expression_tree(detection_rule['expression_tree'], pattern_id_mapping)
        
        return profile
    
    def _remap_expression_tree(self, tree: Dict, pattern_id_mapping: Dict[str, str]):
        """
        Recursively replaces IDs in an expression tree
        """
        if tree.get('rule_item') and tree['rule_item'].get('id') in pattern_id_mapping:
            tree['rule_item']['id'] = pattern_id_mapping[tree['rule_item']['id']]
        
        if tree.get('sub_expressions'):
            for sub_expr in tree['sub_expressions']:
                self._remap_expression_tree(sub_expr, pattern_id_mapping)
    
    def _build_pattern_id_mapping(self, source_patterns: List[Dict], dest_patterns: List[Dict]) -> Dict[str, str]:
        """
        Builds a mapping of pattern IDs between source and destination based on names

        Args:
            source_patterns: Patterns from source tenant
            dest_patterns: Patterns from destination tenant

        Returns:
            Dictionary {source_id: destination_id}
        """
        dest_by_name = {p['name']: p['id'] for p in dest_patterns}
        mapping = {}
        
        for source_pattern in source_patterns:
            source_name = source_pattern['name']
            source_id = source_pattern['id']
            
            if source_name in dest_by_name:
                mapping[source_id] = dest_by_name[source_name]
        
        return mapping
    
    def _build_profile_id_mapping(self, source_profiles: List[Dict], dest_profiles: List[Dict]) -> Dict[int, int]:
        """
        Builds a mapping of profile IDs between source and destination based on names

        Args:
            source_profiles: Profiles from source tenant
            dest_profiles: Profiles from destination tenant

        Returns:
            Dictionary {source_id: destination_id}
        """
        dest_by_name = {p['name']: p['id'] for p in dest_profiles}
        mapping = {}
        
        for source_profile in source_profiles:
            source_name = source_profile['name']
            source_id = source_profile['id']
            
            if source_name in dest_by_name:
                mapping[source_id] = dest_by_name[source_name]
        
        return mapping
    
    def _remap_profile_ids(self, profile: Dict, profile_id_mapping: Dict[int, int]) -> Dict:
        """
        Replaces profile IDs in a granular profile with destination IDs

        Args:
            profile: Profile containing references to other profiles
            profile_id_mapping: Mapping source_ID -> destination_ID for profiles

        Returns:
            Profile with remapped profile IDs
        """
        import copy
        profile = copy.deepcopy(profile)

        # Remap IDs in detection_rules[].multi_profile.data_profile_ids
        if profile.get('detection_rules'):
            for detection_rule in profile['detection_rules']:
                if detection_rule.get('rule_type') == 'multi_profile':
                    multi_profile = detection_rule.get('multi_profile')
                    if multi_profile and multi_profile.get('data_profile_ids'):
                        remapped_ids = []
                        for profile_id in multi_profile['data_profile_ids']:
                            # Use the mapped ID if it exists, otherwise keep the original
                            remapped_ids.append(profile_id_mapping.get(profile_id, profile_id))
                        multi_profile['data_profile_ids'] = remapped_ids
        
        return profile
    
    def compare_patterns(self, source_patterns: List[Dict], dest_patterns: List[Dict], pattern_id_mapping: Dict[str, str] = None, profile_id_mapping: Dict[int, int] = None) -> Tuple[List[Dict], List[Dict], List[Dict]]:
        """
        Compares source and destination patterns

        Args:
            source_patterns: Source patterns/profiles
            dest_patterns: Destination patterns/profiles
            pattern_id_mapping: Optional mapping to remap pattern IDs (for profiles)
            profile_id_mapping: Optional mapping to remap profile IDs (for granular profiles)

        Returns:
            Tuple of (patterns_to_create, patterns_to_update, identical_patterns)
        """
        # Create dictionaries indexed by name to facilitate comparison
        source_dict = {p['name']: p for p in source_patterns}
        dest_dict = {p['name']: p for p in dest_patterns}
        
        to_create = []
        to_update = []
        identical = []
        
        for name, source_pattern in source_dict.items():
            if name not in dest_dict:
                # Pattern doesn't exist in destination
                to_create.append(source_pattern)
            else:
                # Compare normalized versions
                source_norm = self._normalize_pattern(source_pattern)

                # If a mapping is provided (for profiles), remap IDs before comparison
                if pattern_id_mapping:
                    source_norm = self._remap_pattern_ids(source_norm, pattern_id_mapping)

                # If a profile ID mapping is provided, also remap these IDs
                if profile_id_mapping:
                    source_norm = self._remap_profile_ids(source_norm, profile_id_mapping)
                
                dest_norm = self._normalize_pattern(dest_dict[name])

                # Exclude technical fields that can vary between tenants
                # supported_confidence_levels is often added automatically by the API
                diff = DeepDiff(
                    source_norm, 
                    dest_norm, 
                    ignore_order=True,
                    exclude_regex_paths=r".*\['supported_confidence_levels'\]"
                )

                if diff:
                    # The patterns are different
                    to_update.append({
                        'source': source_pattern,
                        'destination': dest_dict[name],
                        'diff': diff
                    })
                else:
                    # The patterns are identical
                    identical.append(source_pattern)
        
        return to_create, to_update, identical
    
    def create_pattern(self, pattern: Dict, token: str) -> Dict:
        """
        Creates a new data pattern

        Args:
            pattern: Pattern to create (without metadata)
            token: Authentication token
        """
        # Normalize the pattern to remove metadata
        clean_pattern = self._normalize_pattern(pattern)
        
        response = requests.post(
            self.data_pattern_url,
            headers=self._get_headers(token),
            json=clean_pattern
        )
        
        if response.status_code not in [200, 201]:
            raise Exception(f"Error during creation: {response.status_code} - {response.text}")
        
        return response.json()
    
    def create_profile(self, profile: Dict, token: str, pattern_id_mapping: Dict[str, str], profile_id_mapping: Dict[int, int] = None) -> Dict:
        """
        Creates a new data profile

        Args:
            profile: Profile to create (without metadata)
            token: Authentication token
            pattern_id_mapping: Mapping of pattern IDs source -> destination
            profile_id_mapping: Mapping of profile IDs source -> destination (for granular profiles)
        """
        # Normalize and remap pattern IDs
        clean_profile = self._normalize_pattern(profile)
        clean_profile = self._remap_pattern_ids(clean_profile, pattern_id_mapping)

        # Remap profile IDs if provided (for granular profiles)
        if profile_id_mapping:
            clean_profile = self._remap_profile_ids(clean_profile, profile_id_mapping)

        # The creation API requires a specific endpoint and special format
        create_url = f"{self.data_profile_url}/create"
        payload = {"dataProfile": clean_profile}
        
        response = requests.post(
            create_url,
            headers=self._get_headers(token),
            json=payload
        )
        
        if response.status_code not in [200, 201]:
            raise Exception(f"Error creating profile: {response.status_code} - {response.text}")
        
        return response.json()
    
    def update_pattern(self, pattern_id: str, pattern: Dict, token: str) -> Dict:
        """
        Updates an existing data pattern

        Args:
            pattern_id: ID of the pattern to modify
            pattern: New values (without metadata)
            token: Authentication token
        """
        # Normalize the pattern to remove metadata
        clean_pattern = self._normalize_pattern(pattern)
        
        url = f"{self.data_pattern_url}/{pattern_id}"
        response = requests.put(
            url,
            headers=self._get_headers(token),
            json=clean_pattern
        )
        
        if response.status_code not in [200, 204]:
            raise Exception(f"Error during update: {response.status_code} - {response.text}")
        
        return response.json() if response.text else {"status": "updated"}
    
    def update_profile(self, profile_id: str, profile: Dict, token: str, pattern_id_mapping: Dict[str, str], profile_id_mapping: Dict[int, int] = None) -> Dict:
        """
        Updates an existing data profile

        Args:
            profile_id: ID of the profile to modify
            profile: New values (without metadata)
            token: Authentication token
            pattern_id_mapping: Mapping of pattern IDs source -> destination
            profile_id_mapping: Mapping of profile IDs source -> destination (for granular profiles)
        """
        # Normalize and remap pattern IDs
        clean_profile = self._normalize_pattern(profile)
        clean_profile = self._remap_pattern_ids(clean_profile, pattern_id_mapping)

        # Remap profile IDs if provided (for granular profiles)
        if profile_id_mapping:
            clean_profile = self._remap_profile_ids(clean_profile, profile_id_mapping)

        # The update API requires a special format with dataProfile
        url = f"{self.data_profile_url}/{profile_id}"
        payload = {"dataProfile": clean_profile}
        
        response = requests.put(
            url,
            headers=self._get_headers(token),
            json=payload
        )
        
        if response.status_code not in [200, 204]:
            raise Exception(f"Error updating profile: {response.status_code} - {response.text}")
        
        return response.json() if response.text else {"status": "updated"}
    
    def sync(self, dry_run: bool = True, target_tenants: List[str] = None) -> Dict:
        """
        Synchronizes source configuration to destinations (patterns then profiles)

        Args:
            dry_run: If True, performs only analysis without modifications
            target_tenants: List of tenant names to synchronize (None = all)

        Returns:
            Synchronization report for all tenants
        """
        print("🔄 Retrieving source configuration...\n")
        
        # Retrieve source patterns and profiles
        source_patterns = self.get_data_patterns(self.source_token)
        source_profiles = self.get_data_profiles(self.source_token)
        print(f"📊 Source ({self.source_creds.get('name', 'Source')}):")
        print(f"   - {len(source_patterns)} custom data patterns")
        print(f"   - {len(source_profiles)} custom data profiles\n")

        # Determine which tenants to synchronize
        tenants_to_sync = self.destinations
        if target_tenants:
            tenants_to_sync = [d for d in self.destinations if d['name'] in target_tenants]
            if not tenants_to_sync:
                print(f"⚠️  No tenant found among: {target_tenants}")
                return {}

        # Global report
        global_report = {
            'source_name': self.source_creds.get('name', 'Source'),
            'source_patterns_count': len(source_patterns),
            'source_profiles_count': len(source_profiles),
            'tenants': {}
        }

        # Synchronize each destination tenant
        for dest in tenants_to_sync:
            print("=" * 80)
            print(f"🎯 TENANT: {dest['name']}")
            print("=" * 80)
            
            try:
                # ===== STEP 1: DATA PATTERNS SYNCHRONIZATION =====
                print("\n📦 STEP 1: DATA PATTERNS SYNCHRONIZATION")
                print("-" * 80)

                # Retrieve destination patterns
                dest_patterns = self.get_data_patterns(dest['token'])
                print(f"📊 Destination: {len(dest_patterns)} custom patterns")

                # Compare
                patterns_to_create, patterns_to_update, patterns_identical = self.compare_patterns(source_patterns, dest_patterns)
                
                report = {
                    'patterns': {
                        'to_create': len(patterns_to_create),
                        'to_update': len(patterns_to_update),
                        'identical': len(patterns_identical),
                        'created': [],
                        'updated': [],
                        'errors': []
                    },
                    'profiles': {
                        'to_create': 0,
                        'to_update': 0,
                        'identical': 0,
                        'created': [],
                        'updated': [],
                        'errors': []
                    }
                }

                # Display patterns summary
                print(f"\n✅ Identical: {len(patterns_identical)}")
                print(f"➕ To create: {len(patterns_to_create)}")
                print(f"🔄 To update: {len(patterns_to_update)}")

                if patterns_to_create:
                    print("\n➕ Patterns to create:")
                    for pattern in patterns_to_create:
                        print(f"   - {pattern['name']}")

                if patterns_to_update:
                    print("\n🔄 Patterns to update:")
                    for item in patterns_to_update:
                        print(f"   - {item['source']['name']}")
                        if dry_run:
                            print(f"     Differences: {item['diff']}")

                # If not dry_run, create/update patterns
                if not dry_run:
                    print("\n" + "-" * 80)
                    print("🚀 EXECUTING MODIFICATIONS (PATTERNS)")
                    print("-" * 80)

                    # Create new patterns
                    if patterns_to_create:
                        print(f"\n➕ Creating {len(patterns_to_create)} patterns...")
                        for pattern in patterns_to_create:
                            try:
                                result = self.create_pattern(pattern, dest['token'])
                                report['patterns']['created'].append(pattern['name'])
                                print(f"   ✅ Created: {pattern['name']}")
                            except Exception as e:
                                error_msg = f"Error creating {pattern['name']}: {str(e)}"
                                report['patterns']['errors'].append(error_msg)
                                print(f"   ❌ {error_msg}")

                    # Update existing patterns
                    if patterns_to_update:
                        print(f"\n🔄 Updating {len(patterns_to_update)} patterns...")
                        for item in patterns_to_update:
                            try:
                                dest_id = item['destination']['id']
                                result = self.update_pattern(dest_id, item['source'], dest['token'])
                                report['patterns']['updated'].append(item['source']['name'])
                                print(f"   ✅ Updated: {item['source']['name']}")
                            except Exception as e:
                                error_msg = f"Error updating {item['source']['name']}: {str(e)}"
                                report['patterns']['errors'].append(error_msg)
                                print(f"   ❌ {error_msg}")

                    # Reload destination patterns after modification
                    print("\n🔄 Reloading destination patterns...")
                    dest_patterns = self.get_data_patterns(dest['token'])

                # ===== STEP 2: DATA PROFILES SYNCHRONIZATION =====
                print("\n\n📋 STEP 2: DATA PROFILES SYNCHRONIZATION")
                print("-" * 80)

                # Build pattern ID mapping (ALL patterns, not just custom)
                all_source_patterns = self.get_data_patterns(self.source_token, custom_only=False)
                all_dest_patterns = self.get_data_patterns(dest['token'], custom_only=False)
                pattern_id_mapping = self._build_pattern_id_mapping(all_source_patterns, all_dest_patterns)
                print(f"🔗 Mapping {len(pattern_id_mapping)} patterns source -> destination")

                # Retrieve destination profiles
                dest_profiles = self.get_data_profiles(dest['token'])
                print(f"📊 Destination: {len(dest_profiles)} custom profiles")

                # Build profile ID mapping (for granular profiles)
                profile_id_mapping = self._build_profile_id_mapping(source_profiles, dest_profiles)
                print(f"🔗 Mapping {len(profile_id_mapping)} profiles source -> destination")
                
                # Compare profiles (with remapping of pattern and profile IDs)
                profiles_to_create, profiles_to_update, profiles_identical = self.compare_patterns(
                    source_profiles, dest_profiles, pattern_id_mapping, profile_id_mapping
                )

                report['profiles']['to_create'] = len(profiles_to_create)
                report['profiles']['to_update'] = len(profiles_to_update)
                report['profiles']['identical'] = len(profiles_identical)

                # Display profiles summary
                print(f"\n✅ Identical: {len(profiles_identical)}")
                print(f"➕ To create: {len(profiles_to_create)}")
                print(f"🔄 To update: {len(profiles_to_update)}")

                if profiles_to_create:
                    print("\n➕ Profiles to create:")
                    for profile in profiles_to_create:
                        print(f"   - {profile['name']}")

                if profiles_to_update:
                    print("\n🔄 Profiles to update:")
                    for item in profiles_to_update:
                        print(f"   - {item['source']['name']}")
                        if dry_run:
                            print(f"     Differences: {item['diff']}")

                # If dry_run, skip to next tenant
                if dry_run:
                    print("\n⚠️  DRY RUN Mode - No modifications made")
                    global_report['tenants'][dest['name']] = report
                    print()
                    continue

                # If not dry_run, create/update profiles
                print("\n" + "-" * 80)
                print("🚀 EXECUTING MODIFICATIONS (PROFILES)")
                print("-" * 80)

                # Create new profiles
                if profiles_to_create:
                    print(f"\n➕ Creating {len(profiles_to_create)} profiles...")
                    for profile in profiles_to_create:
                        try:
                            result = self.create_profile(profile, dest['token'], pattern_id_mapping, profile_id_mapping)
                            report['profiles']['created'].append(profile['name'])
                            print(f"   ✅ Created: {profile['name']}")
                        except Exception as e:
                            error_msg = f"Error creating {profile['name']}: {str(e)}"
                            report['profiles']['errors'].append(error_msg)
                            print(f"   ❌ {error_msg}")

                # Update existing profiles
                if profiles_to_update:
                    print(f"\n🔄 Updating {len(profiles_to_update)} profiles...")
                    for item in profiles_to_update:
                        try:
                            dest_id = item['destination']['id']
                            result = self.update_profile(dest_id, item['source'], dest['token'], pattern_id_mapping, profile_id_mapping)
                            report['profiles']['updated'].append(item['source']['name'])
                            print(f"   ✅ Updated: {item['source']['name']}")
                        except Exception as e:
                            error_msg = f"Error updating {item['source']['name']}: {str(e)}"
                            report['profiles']['errors'].append(error_msg)
                            print(f"   ❌ {error_msg}")

                print(f"\n✅ Synchronization of {dest['name']} completed")
                print(f"   Patterns - Created: {len(report['patterns']['created'])}, Updated: {len(report['patterns']['updated'])}, Errors: {len(report['patterns']['errors'])}")
                print(f"   Profiles - Created: {len(report['profiles']['created'])}, Updated: {len(report['profiles']['updated'])}, Errors: {len(report['profiles']['errors'])}")
                
                global_report['tenants'][dest['name']] = report
                
            except Exception as e:
                print(f"\n❌ Error during synchronization of {dest['name']}: {str(e)}")
                global_report['tenants'][dest['name']] = {
                    'error': str(e)
                }

            print()

        # Display global summary
        print("=" * 80)
        print("📊 GLOBAL SYNCHRONIZATION SUMMARY")
        print("=" * 80)

        for tenant_name, report in global_report['tenants'].items():
            if 'error' in report:
                print(f"❌ {tenant_name}: ERROR - {report['error']}")
            else:
                status = "DRY RUN" if dry_run else "COMPLETED"
                print(f"✅ {tenant_name}: {status}")
                print(f"   Patterns - Identical: {report['patterns']['identical']} | To create: {report['patterns']['to_create']} | To update: {report['patterns']['to_update']}")
                print(f"   Profiles - Identical: {report['profiles']['identical']} | To create: {report['profiles']['to_create']} | To update: {report['profiles']['to_update']}")
                if not dry_run:
                    print(f"   Patterns - Created: {len(report['patterns']['created'])} | Updated: {len(report['patterns']['updated'])} | Errors: {len(report['patterns']['errors'])}")
                    print(f"   Profiles - Created: {len(report['profiles']['created'])} | Updated: {len(report['profiles']['updated'])} | Errors: {len(report['profiles']['errors'])}")
        
        return global_report


# --- USAGE EXAMPLE ---
if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description='Synchronizes DLP configuration between Prisma Access tenants',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage examples:
  # Analysis (dry run) of all tenants
  python pa_sync.py

  # Direct synchronization of all tenants (without confirmation)
  python pa_sync.py --execute --all

  # Synchronization of a specific tenant
  python pa_sync.py --execute --tenant "Prod"

  # Synchronization of multiple specific tenants
  python pa_sync.py --execute --tenant "Prod" --tenant "Dev"
        """
    )
    
    parser.add_argument(
        '--execute', '--no-dry-run',
        action='store_true',
        dest='execute',
        help='Executes the synchronization (without dry run)'
    )

    parser.add_argument(
        '--all',
        action='store_true',
        help='Synchronizes all tenants without interactive confirmation'
    )

    parser.add_argument(
        '--tenant', '-t',
        action='append',
        dest='tenants',
        help='Name of tenant to synchronize (can be specified multiple times)'
    )
    
    args = parser.parse_args()

    # Load configuration from YAML file
    config_file = Path(__file__).parent / "config.yaml"

    if not config_file.exists():
        print(f"❌ Configuration file not found: {config_file}")
        print("Please create a config.yaml file with your credentials")
        exit(1)
    
    with open(config_file, 'r') as f:
        config = yaml.safe_load(f)

    # Configure source tenant from YAML
    source_config = config['source']
    source_creds = {
        'service_account': source_config['service_account'],
        'api_key': source_config['api_key'],
        'scope': f"tsg_id:{source_config['tsg_id']}",
        'name': source_config.get('name', 'Source')
    }

    # Configure destination tenants from YAML
    dest_creds_list = []
    for dest_config in config['destinations']:
        dest_creds_list.append({
            'service_account': dest_config['service_account'],
            'api_key': dest_config['api_key'],
            'scope': f"tsg_id:{dest_config['tsg_id']}",
            'name': dest_config.get('name', f"Tenant {len(dest_creds_list) + 1}")
        })

    # Initialize the synchronizer with all tenants
    print("🔐 Authentication in progress...\n")
    syncer = PrismaAccessSync(source_creds, dest_creds_list)

    # Determine execution mode
    dry_run = not args.execute

    if args.all and args.execute:
        # Mode: Automatic synchronization of all tenants
        print("\n" + "=" * 80)
        print("MODE: Automatic synchronization of all tenants")
        print("=" * 80 + "\n")
        report = syncer.sync(dry_run=False)

    elif args.tenants:
        # Mode: Synchronization of specific tenants
        target_names = args.tenants
        print("\n" + "=" * 80)
        mode = "Synchronization" if args.execute else "Analysis (DRY RUN)"
        print(f"MODE: {mode} of tenants: {', '.join(target_names)}")
        print("=" * 80 + "\n")
        report = syncer.sync(dry_run=dry_run, target_tenants=target_names)

    elif args.execute:
        # Mode: Interactive synchronization
        print("\n" + "=" * 80)
        print("MODE: Interactive synchronization")
        print("=" * 80 + "\n")

        # First do a dry run to show what will be done
        print("📊 Preliminary analysis...\n")
        report = syncer.sync(dry_run=True)

        # Ask for confirmation for each tenant
        for dest in syncer.destinations:
            print(f"\n{'=' * 80}")
            print(f"Do you want to synchronize tenant: {dest['name']}? (yes/no): ", end='')
            if input().lower() == 'yes':
                syncer.sync(dry_run=False, target_tenants=[dest['name']])
            else:
                print(f"⏭️  {dest['name']} skipped")

    else:
        # Default mode: Dry run of all tenants
        print("\n" + "=" * 80)
        print("MODE: Analysis of all tenants (DRY RUN)")
        print("=" * 80 + "\n")
        report = syncer.sync(dry_run=True)

        print(f"\n{'=' * 80}")
        print("💡 To execute synchronization, use: python pa_sync.py --execute")
        print("=" * 80)