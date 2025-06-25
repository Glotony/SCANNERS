# SCANNERS

This project is a torrent and IP scanner tool with features like:

- Cleaning torrent files by removing bad trackers
- Checking peers (IP addresses) against VirusTotal
- Maintaining blocklists of malicious domains and IPs in MongoDB
- Scanning `.exe` files from torrents for malware and moving threats to a quarantine folder

## Project Structure


## Requirements

- Python 3.8+
- MongoDB instance (local or cloud)
- VirusTotal API key

## Setup

1. Clone the repo  
   `git clone https://github.com/Glotony/SCANNERS.git`

2. Create and activate a virtual environment  


3. Install dependencies  
`pip install -r requirements.txt`

4. Create a `.env` file with your keys:  


5. Place your torrents in `__torrent__/` and peers in `peers.json`

6. Run the scanner:  
`python your_script.py`  (replace with your actual script name)

## Notes

- Make sure MongoDB is running and accessible
- Rate limits apply for VirusTotal API, so scanning may take time
- Detected bad `.exe` files are moved to `delete_exe/` folder for manual review

---

If you want me to add more sections or details, just say!
