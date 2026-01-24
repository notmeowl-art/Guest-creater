import json
import os

def fast_json_converter():
    input_file = 'accounts.txt'
    target_region = "BD"

    # ১. চেক করা ফাইলটি আছে কি না
    if not os.path.exists(input_file):
        print(f"Error: {input_file} খুঁজে পাওয়া যায়নি!")
        return

    # ২. আউটপুট ফাইলের নাম ঠিক করা (accounts-1.json, 2, 3...)
    counter = 1
    while True:
        output_file = f"accounts-{counter}.json"
        if not os.path.exists(output_file):
            break
        counter += 1

    formatted_data = []

    # ৩. দ্রুত ডেটা রিড এবং ফরম্যাট করা
    try:
        with open(input_file, 'r') as f:
            for line in f:
                line = line.strip()
                if ':' in line:
                    uid, password = line.split(':', 1)
                    formatted_data.append({
                        "uid": int(uid),
                        "password": password,
                        "region": target_region
                    })

        # ৪. JSON ফাইলে সেভ করা
        if formatted_data:
            with open(output_file, 'w', encoding='utf-8') as jf:
                json.dump(formatted_data, jf, indent=2)
            print(f"Success: {len(formatted_data)} IDs saved to {output_file}")
            
            # ৫. কাজ শেষে মূল ফাইল ডিলিট করা
            os.remove(input_file)
            print(f"Deleted: {input_file} has been removed.")
        else:
            print("No valid data found in accounts.txt")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    fast_json_converter()
