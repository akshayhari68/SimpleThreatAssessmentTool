# Import necessary libraries
import feedparser
import requests
import time
import re
from datetime import datetime, timezone, timedelta
from collections import Counter, defaultdict
import sys # To check for library import

# --- Attempt to import attackcti ---
try:
    from attackcti import AttackCTI
    attack_client = AttackCTI() # Initialize client once
    ATTACKCTI_AVAILABLE = True
    print("MITRE ATT&CK CTI library loaded successfully.")
except ImportError:
    print("Warning: 'attackcti' library not found.")
    print("Please install it using: pip install attackcti")
    print("TTP information will not be available.")
    ATTACKCTI_AVAILABLE = False
    # Define a placeholder if the library is missing to avoid NameErrors later
    attack_client = None
except Exception as e:
    print(f"Warning: Failed to initialize MITRE ATT&CK CTI client: {e}")
    print("TTP information may be unavailable or incomplete.")
    ATTACKCTI_AVAILABLE = False # Treat as unavailable if init fails
    attack_client = None


# --- Configuration ---

# Source URLs
RSS_FEED_URL = "https://www.ransomfeed.it/rss-complete.php"
RANSOMWARE_LIVE_API_URL = "https://api.ransomware.live/posts" # Example endpoint - Verify!

# --- Predefined Profiles for User Selection ---
INDUSTRY_PROFILES = {
    "1": {"name": "Finance/Insurance", "keywords": ['finance', 'banking', 'insurance', 'investment']},
    "2": {"name": "Healthcare/Pharma", "keywords": ['healthcare', 'medical', 'hospital', 'pharma', 'pharmaceutical']},
    "3": {"name": "Technology/IT", "keywords": ['technology', 'software', 'hardware', 'saas', 'cloud', 'it services', 'msp']},
    "4": {"name": "Manufacturing/Industrial", "keywords": ['manufacturing', 'industrial', 'automotive', 'aerospace']},
    "5": {"name": "Retail/Ecommerce", "keywords": ['retail', 'ecommerce', 'consumer goods', 'apparel', 'foods']},
    "6": {"name": "Logistics/Transport", "keywords": ['logistics', 'shipping', 'transport', 'supply chain', 'distribution', 'warehouse']},
    "7": {"name": "Energy/Utilities", "keywords": ['energy', 'utility', 'oil', 'gas', 'power']},
    "8": {"name": "Government/Public Sector", "keywords": ['government', 'public sector', 'municipal', 'federal', 'state', 'local']},
    "9": {"name": "Education", "keywords": ['education', 'university', 'college', 'school']},
    "10": {"name": "Construction/Real Estate", "keywords": ['construction', 'real estate', 'property']},
    "11": {"name": "Legal", "keywords": ['legal', 'law firm']},
    "12": {"name": "Consulting/Professional Services", "keywords": ['consulting', 'professional services']},
    "13": {"name": "Media/Telecom", "keywords": ['media', 'entertainment', 'telecom', 'telecommunications']},
    "14": {"name": "Hospitality/Travel", "keywords": ['hospitality', 'hotel', 'travel']},
}
REGION_PROFILES = {
    "1": {"name": "North America (NA)", "keywords": ['usa', 'canada', 'mexico']},
    "2": {"name": "Europe", "keywords": ['uk', 'united kingdom', 'germany', 'france', 'italy', 'spain', 'eu', 'europe']},
    "3": {"name": "Asia-Pacific (APAC)", "keywords": ['australia', 'new zealand', 'oceania', 'china', 'japan', 'korea', 'india', 'singapore', 'indonesia', 'fiji', 'apac', 'asia', 'asia pacific']},
    "4": {"name": "Latin America (LATAM)", "keywords": ['brazil', 'argentina', 'colombia', 'mexico', 'latin america', 'south america']},
    "5": {"name": "Middle East & Africa (MEA)", "keywords": ['uae', 'saudi arabia', 'south africa', 'nigeria', 'middle east', 'africa']},
}

# --- Actor Analysis Configuration ---
ACTOR_ANALYSIS_WEIGHTS = {
    'industry_hit': 2,
    'country_hit': 3 # Weighted higher for country match
}
TOP_N_ACTORS_TO_SHOW = 10
MAX_RECENT_HITS_TO_SHOW = 3

# --- Helper Functions ---

def clean_html(raw_html):
    """Removes HTML tags."""
    if not raw_html: return ""
    cleanr = re.compile('<.*?>'); cleantext = re.sub(cleanr, '', raw_html)
    return cleantext.replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>').strip()

def extract_matching_keywords(text, keyword_list):
    """Finds which keywords from the provided list exist in the text."""
    found = []
    if not text or not keyword_list: return found
    text_lower = text.lower()
    for keyword in keyword_list:
        if re.search(r'\b' + re.escape(keyword.lower()) + r'\b', text_lower):
            if keyword not in found: found.append(keyword)
    return found

def extract_threat_actor_rss(entry, description_html):
    """Extracts threat actor from Ransomfeed RSS."""
    actor = entry.get('category');
    if actor: return actor.strip()
    if description_html:
        match = re.search(r'group called\s*<b>\s*([^<]+)\s*</b>', description_html, re.IGNORECASE)
        if match: return match.group(1).strip()
    return "Unknown"

def parse_iso_datetime(date_string):
    """Parses ISO 8601 dates."""
    if not date_string: return None
    try:
        # Handle potential 'Z' for UTC and microseconds more robustly
        dt_naive = datetime.fromisoformat(date_string.replace('Z', ''))
        # Assume UTC if no timezone info present after removing Z
        if dt_naive.tzinfo is None:
            return dt_naive.replace(tzinfo=timezone.utc)
        return dt_naive
    except Exception as e:
        print(f"Warning: Date parse error '{date_string}': {e}")
        return None


def parse_rfc822_datetime(time_struct):
    """Converts feedparser time.struct_time to datetime."""
    if not time_struct: return None
    try:
        # feedparser usually parses dates into GMT/UTC
        dt_naive = datetime.fromtimestamp(time.mktime(time_struct))
        return dt_naive.replace(tzinfo=timezone.utc) # Assume UTC
    except Exception as e: print(f"Warning: Time struct error {time_struct}: {e}"); return None

# --- Data Fetching and Normalization ---

def fetch_rss_feed(url):
    """Fetches and parses RSS feed, normalizes entries."""
    print(f"Fetching RSS feed from: {url}")
    normalized_entries = []
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (compatible; SimpleThreatIntelScript/1.0)'} # Version bump
        feed = feedparser.parse(url, agent=headers.get('User-Agent'))
        if feed.bozo: print(f"Warning: RSS feed malformed. Reason: {feed.bozo_exception}")
        if hasattr(feed, 'status') and feed.status != 200: print(f"Error: RSS HTTP {feed.status}."); return []
        elif not feed.entries and not feed.feed: print("Error: No RSS data."); return []
        for entry in feed.entries:
            description_html = entry.get('description', entry.get('summary', ''))
            actor = extract_threat_actor_rss(entry, description_html)
            pub_date = parse_rfc822_datetime(entry.get('published_parsed'))
            victim_name = entry.get('title', 'No Title')
            description_clean = clean_html(description_html)
            search_context = f"{victim_name} {description_clean}"
            pub_date_iso = pub_date.isoformat() if pub_date else None

            normalized = {
                'id': entry.get('guid', entry.get('link', entry.get('title'))),
                'victim': victim_name,
                'threat_actor': actor,
                'link': entry.get('link', ''),
                'published_date': pub_date, # Keep datetime object
                'published_date_iso': pub_date_iso,
                'description': description_clean,
                'search_context': search_context,
                'source': 'Ransomfeed.it RSS'
            }
            normalized_entries.append(normalized)
    except Exception as e: print(f"Error fetching/parsing RSS: {e}")
    return normalized_entries

def fetch_ransomware_live_api(url):
    """Fetches data from Ransomware.live API, normalizes entries."""
    print(f"Fetching API data from: {url}")
    normalized_entries = []
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (compatible; SimpleThreatIntelScript/1.0)'}
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()
        if isinstance(data, list):
             for item in data:
                 victim_name = item.get('post_title', item.get('victim', 'No Title'))
                 threat_actor = item.get('group_name', item.get('threat_actor', 'Unknown'))
                 pub_date_str = item.get('discovered', item.get('published', item.get('created_at')))
                 description = item.get('description', '')
                 link = item.get('post_url', item.get('url', item.get('link', ''))) # Verify this!
                 entry_id = item.get('id', f"{victim_name}_{pub_date_str}")
                 pub_date = parse_iso_datetime(pub_date_str) # Returns timezone-aware datetime
                 description_clean = clean_html(description)
                 search_context = f"{victim_name} {description_clean}"
                 pub_date_iso = pub_date.isoformat() if pub_date else None

                 normalized = {
                     'id': entry_id,
                     'victim': victim_name,
                     'threat_actor': threat_actor,
                     'link': link,
                     'published_date': pub_date, # Keep datetime object
                     'published_date_iso': pub_date_iso,
                     'description': description_clean,
                     'search_context': search_context,
                     'source': 'Ransomware.live API'
                 }
                 normalized_entries.append(normalized)
        else: print(f"Warning: Unexpected API response format: {type(data)}.")
    except requests.exceptions.RequestException as e: print(f"Error fetching API data: {e}")
    except Exception as e: print(f"Error processing API data: {e}")
    return normalized_entries


# --- TTP Fetching ---
# Cache for fetched TTPs to avoid repeated lookups
ttp_cache = {}

def get_actor_ttps(actor_name):
    """Fetches TTPs for a given actor name using attackcti."""
    global attack_client # Ensure we use the globally initialized client
    if not ATTACKCTI_AVAILABLE or not actor_name or actor_name == "Unknown" or attack_client is None:
        return {} # Return empty if library unavailable or actor unknown or client failed init

    # Check cache first (use lowercase for consistency)
    actor_name_lower = actor_name.lower()
    if actor_name_lower in ttp_cache:
        return ttp_cache[actor_name_lower]

    print(f"Fetching TTPs for {actor_name} from MITRE ATT&CK CTI...")
    try:
        # Use get_techniques_used_by_group - requires exact name or alias match
        techniques = attack_client.get_techniques_used_by_group(actor_name, include_subtechniques=False)

        if not techniques:
             print(f" - No direct match found for '{actor_name}'.")
             ttp_cache[actor_name_lower] = {}
             return {}

        ttp_dict = {}
        for tech in techniques:
            tech_id = getattr(tech, 'external_references', [{}])[0].get('external_id', 'N/A')
            tech_name = getattr(tech, 'name', 'Unknown Technique Name')
            if tech_id != 'N/A':
                 ttp_dict[tech_id] = tech_name

        print(f" - Found {len(ttp_dict)} TTPs for {actor_name}.")
        ttp_cache[actor_name_lower] = ttp_dict # Cache result
        return ttp_dict

    except Exception as e:
        print(f" - Error fetching TTPs for {actor_name}: {e}")
        ttp_cache[actor_name_lower] = {} # Cache empty result on error
        return {}

# --- Actor Targeting Analysis ---

def analyze_actor_targeting(entries, selected_industry_keywords, selected_country_keywords):
    """
    Analyzes entries to identify actors targeting the selected profile.
    Stores details of hits, counts per country, fetches TTPs, and calculates weighted score.
    """
    print(f"\nAnalyzing {len(entries)} entries for actor targeting...")
    # Structure now includes 'ttps' field
    actor_stats = defaultdict(lambda: {
        'total_hits': 0, 'industry_hits': 0, 'region_hits': 0, # region_hits counts country matches
        'country_profile_hits': [], 'country_hit_counts': Counter(),
        'score': 0, 'ttps': {} # Add field for TTPs
    })
    if not entries: return {}

    # Sort entries by date first
    entries.sort(key=lambda x: x.get('published_date') or datetime.min.replace(tzinfo=timezone.utc), reverse=True)

    processed_actors = set() # Keep track of actors for whom TTPs have been fetched

    for entry in entries:
        actor = entry.get('threat_actor')
        if not actor or actor == "Unknown": continue

        search_context = entry.get('search_context', '')
        actor_stats[actor]['total_hits'] += 1

        # Fetch TTPs once per actor
        if actor not in processed_actors:
            actor_stats[actor]['ttps'] = get_actor_ttps(actor)
            processed_actors.add(actor)

        # Check industry match
        found_industry_kws = extract_matching_keywords(search_context, selected_industry_keywords)
        if found_industry_kws:
            actor_stats[actor]['industry_hits'] += 1

        # Check country/sub-region match
        found_country_kws = extract_matching_keywords(search_context, selected_country_keywords)
        if found_country_kws:
            actor_stats[actor]['region_hits'] += 1 # Increment total country hits count
            hit_date = entry.get('published_date')
            hit_victim = entry.get('victim', 'N/A')
            hit_link = entry.get('link', '')
            if hit_date and hit_link:
                actor_stats[actor]['country_profile_hits'].append((hit_date, hit_victim, hit_link))
            for country_kw in found_country_kws:
                 actor_stats[actor]['country_hit_counts'][country_kw] += 1

    # Calculate weighted score after processing all entries
    for actor, stats in actor_stats.items():
         stats['score'] = (stats['industry_hits'] * ACTOR_ANALYSIS_WEIGHTS['industry_hit'] +
                           stats['region_hits'] * ACTOR_ANALYSIS_WEIGHTS['country_hit'])

    print(f"Analysis complete for {len(actor_stats)} unique known actors.")
    return dict(actor_stats)

def display_potential_actors(actor_stats, selected_industries_names, selected_countries_names):
    """Displays top actors based on weighted score, showing country hits and fetched TTPs."""
    if not actor_stats: print("No relevant actor statistics found for the selected profile."); return

    profile_desc = f"Profile: Industries ({', '.join(selected_industries_names)}), Countries/Sub-regions ({', '.join(selected_countries_names)})"
    print(f"\n--- Top Threat Actors Potentially Targeting Your Profile ---")
    print(f"({profile_desc})")
    print("(Based on victim matches, ranked by weighted relevance. TTPs from MITRE ATT&CK CTI)")

    actor_scores = []
    for actor, stats in actor_stats.items():
        if stats['score'] > 0:
            actor_scores.append({
                'name': actor,
                'score': stats['score'],
                'industry_hits': stats['industry_hits'],
                'region_hits': stats['region_hits'],
                'total_hits': stats['total_hits'],
                'country_profile_hits': stats['country_profile_hits'],
                'country_hit_counts': stats['country_hit_counts'],
                'ttps': stats['ttps'] # Include fetched TTPs
            })

    actor_scores.sort(key=lambda x: (x['score'], x['total_hits']), reverse=True)

    if not actor_scores:
        print("\nNo actors found with hits specifically matching the selected profile.")
        return

    for i, actor_info in enumerate(actor_scores[:TOP_N_ACTORS_TO_SHOW]):
        print(f"\n{i+1}. {actor_info['name']}")
        # Score is not displayed
        print(f"   Industry Hits (Matching Profile): {actor_info['industry_hits']}")
        print(f"   Country Hits (Matching Profile Total): {actor_info['region_hits']}")
        print(f"   Total Hits (Overall): {actor_info['total_hits']}")

        # Display Country Hit Breakdown
        country_counts = actor_info.get('country_hit_counts')
        if country_counts:
            print(f"   Country Hit Breakdown:")
            for country, count in country_counts.most_common(): print(f"     - {country}: {count}")

        # Display Fetched TTPs
        ttp_dict = actor_info.get('ttps', {})
        if ttp_dict:
            print(f"   Associated TTPs (MITRE ATT&CK):")
            for ttp_id, ttp_name in sorted(ttp_dict.items()):
                print(f"     - {ttp_id}: {ttp_name}")
        elif ATTACKCTI_AVAILABLE:
             print(f"   Associated TTPs (MITRE ATT&CK): Not found or no TTPs listed in CTI for this group.")
        else:
             print(f"   Associated TTPs (MITRE ATT&CK): Library not available.")


        # Display Recent Hits Matching Selected Countries/Sub-regions
        country_hits = actor_info.get('country_profile_hits', [])
        if country_hits:
            print(f"   Latest Hits Matching Selected Countries/Sub-regions (Max {MAX_RECENT_HITS_TO_SHOW}):")
            for hit_date, hit_victim, hit_link in country_hits[:MAX_RECENT_HITS_TO_SHOW]:
                 date_str = hit_date.strftime('%Y-%m-%d') if hit_date else "Unknown Date"
                 print(f"     - {date_str} | Victim: {hit_victim} | Link: {hit_link}")
        else:
            print(f"   Latest Hits Matching Selected Countries/Sub-regions: None found.")


# --- Input Handling ---
# (get_profile_selection function remains the same)
def get_profile_selection(profile_options, profile_type, is_region=False):
    """Gets user selection from a list of profile options."""
    print(f"\n--- Select Relevant {profile_type}s ---")
    for key, value in profile_options.items(): print(f"{key}: {value['name']}")
    print("------------------------------------")
    selected_keys = []
    while not selected_keys:
        prompt_text = f"Enter number(s) for relevant {profile_type}s (comma-separated): "
        user_input = input(prompt_text).strip()
        selected_keys_raw = [k.strip() for k in user_input.split(',') if k.strip()]
        valid_keys = [k for k in selected_keys_raw if k in profile_options]
        if not valid_keys: print(f"Invalid selection. Please enter numbers from the list.")
        else: selected_keys = valid_keys
    initial_selected_keywords = []; initial_selected_names = []
    for key in selected_keys:
        initial_selected_keywords.extend(profile_options[key]['keywords'])
        initial_selected_names.append(profile_options[key]['name'])
    unique_initial_keywords = sorted(list(set(initial_selected_keywords)))
    if is_region:
        if not unique_initial_keywords:
             print("No specific countries/sub-regions found in the selected region profiles.")
             return [], initial_selected_names
        print(f"\n--- Select Specific Countries/Sub-regions from '{', '.join(initial_selected_names)}' ---")
        country_options = {str(i+1): kw for i, kw in enumerate(unique_initial_keywords)}
        for key, value in country_options.items(): print(f"{key}: {value}")
        print("------------------------------------")
        final_selected_keys_indices = []
        while not final_selected_keys_indices:
            user_input_countries = input(f"Enter number(s) for specific countries/sub-regions (comma-separated): ").strip()
            selected_keys_raw_countries = [k.strip() for k in user_input_countries.split(',') if k.strip()]
            valid_keys_indices = [k for k in selected_keys_raw_countries if k in country_options]
            if not valid_keys_indices: print(f"Invalid selection. Please enter numbers from the specific list.")
            else: final_selected_keys_indices = valid_keys_indices
        final_selected_keywords = [country_options[key] for key in final_selected_keys_indices]
        final_selected_names = final_selected_keywords
        print(f"Selected Countries/Sub-regions: {', '.join(final_selected_names)}")
        return final_selected_keywords, final_selected_names
    else:
        print(f"Selected {profile_type}s: {', '.join(initial_selected_names)}")
        return unique_initial_keywords, initial_selected_names

# --- Main Execution ---
if __name__ == "__main__":
    print("Starting Threat Actor Prediction Script...")

    # 1. Fetch data
    rss_entries = fetch_rss_feed(RSS_FEED_URL)
    api_entries = fetch_ransomware_live_api(RANSOMWARE_LIVE_API_URL) # Adapt API parsing if needed

    # 2. Combine and Deduplicate
    combined_entries = {}
    all_raw_entries = rss_entries + api_entries
    print(f"\nFetched {len(all_raw_entries)} raw entries total.")
    if not all_raw_entries: print("No data fetched. Exiting."); exit()

    for entry in all_raw_entries:
        entry_id = entry.get('id')
        if not entry_id:
             date_part = entry.get('published_date_iso', str(time.time()))
             entry_id = f"{entry.get('victim', '').lower()}_{date_part}"
        existing_entry = combined_entries.get(entry_id)
        if not existing_entry or \
           (entry.get('published_date') and existing_entry.get('published_date') and \
            entry['published_date'] > existing_entry['published_date']):
             combined_entries[entry_id] = entry
        elif not existing_entry: combined_entries[entry_id] = entry
    deduplicated_list = list(combined_entries.values())
    print(f"Combined into {len(deduplicated_list)} unique entries.")

    # 3. Get User Profile Selection
    selected_industry_keywords, selected_industries_names = get_profile_selection(INDUSTRY_PROFILES, "Industry")
    selected_country_keywords, selected_countries_names = get_profile_selection(REGION_PROFILES, "Region", is_region=True)

    # 4. Analyze Actor Targeting (includes TTP fetching)
    actor_analysis_results = analyze_actor_targeting(
        deduplicated_list,
        selected_industry_keywords,
        selected_country_keywords
    )

    # 5. Display Potential Actors (includes dynamic TTPs)
    display_potential_actors(
        actor_analysis_results,
        selected_industries_names,
        selected_countries_names
    )

    print("\nScript finished.")
