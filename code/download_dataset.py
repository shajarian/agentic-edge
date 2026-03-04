import requests
from bs4 import BeautifulSoup
import os
from urllib.parse import urljoin, unquote, urlparse

base_url = "http://cicresearch.ca/IOTDataset/CIC%20IoT-IDAD%20Dataset%202024/Dataset/"

# Track visited URLs to avoid infinite loops
visited_urls = set()

def download_files(url, save_dir="CIC_IoT_Dataset", depth=0, max_depth=10):
    """
    Recursively download files from a directory listing
    
    Args:
        url: URL to download from
        save_dir: Local directory to save files
        depth: Current recursion depth
        max_depth: Maximum recursion depth allowed
    """
    
    # Prevent infinite recursion
    if depth > max_depth:
        print(f"⚠️  Max depth reached at: {url}")
        return
    
    # Normalize URL and check if already visited
    normalized_url = url.rstrip('/')
    if normalized_url in visited_urls:
        print(f"⏭️  Already visited: {url}")
        return
    
    visited_urls.add(normalized_url)
    
    # Create directory
    os.makedirs(save_dir, exist_ok=True)
    
    try:
        print(f"{'  ' * depth}📂 Checking: {url}")
        response = requests.get(url, timeout=30)
        soup = BeautifulSoup(response.content, 'html.parser')
        
        for link in soup.find_all('a'):
            href = link.get('href')
            
            # Skip navigation links
            if not href or href.startswith('?') or href == '../' or href.startswith('/'):
                continue
            
            # Build full URL
            file_url = urljoin(url, href)
            file_name = unquote(href.rstrip('/'))
            
            # Skip if it's going back up the directory tree
            if '..' in file_name:
                continue
            
            if href.endswith('/'):  # It's a directory
                subdir_name = file_name
                print(f"{'  ' * depth}📁 Entering: {subdir_name}")
                download_files(file_url, os.path.join(save_dir, subdir_name), depth + 1, max_depth)
            else:  # It's a file
                file_path = os.path.join(save_dir, file_name)
                
                # Skip if file already exists
                if os.path.exists(file_path):
                    print(f"{'  ' * depth}✓ Already downloaded: {file_name}")
                    continue
                
                print(f"{'  ' * depth}⬇️  Downloading: {file_name}")
                
                try:
                    file_response = requests.get(file_url, stream=True, timeout=60)
                    total_size = int(file_response.headers.get('content-length', 0))
                    
                    with open(file_path, 'wb') as f:
                        downloaded = 0
                        for chunk in file_response.iter_content(chunk_size=1024*1024):
                            f.write(chunk)
                            downloaded += len(chunk)
                            if total_size > 0:
                                percent = (downloaded / total_size) * 100
                                mb_downloaded = downloaded / (1024*1024)
                                mb_total = total_size / (1024*1024)
                                print(f"{'  ' * depth}   Progress: {percent:.1f}% ({mb_downloaded:.1f}/{mb_total:.1f} MB)", end='\r')
                    
                    print(f"{'  ' * depth}   ✅ Complete: {file_name}                    ")
                    
                except Exception as e:
                    print(f"{'  ' * depth}   ❌ Failed to download {file_name}: {e}")
                    # Remove partial file
                    if os.path.exists(file_path):
                        os.remove(file_path)
                    
    except Exception as e:
        print(f"{'  ' * depth}❌ Error accessing {url}: {e}")

if __name__ == "__main__":
    print("=" * 60)
    print("CIC IoT-DIAD 2024 Dataset Downloader")
    print("=" * 60)
    print(f"Downloading from: {base_url}")
    print(f"Saving to: ./CIC_IoT_Dataset/")
    print("=" * 60)
    print()
    
    download_files(base_url)
    
    print()
    print("=" * 60)
    print("🎉 Download process complete!")
    print(f"📊 Total URLs visited: {len(visited_urls)}")
    print("=" * 60)