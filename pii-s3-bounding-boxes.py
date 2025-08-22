import json
import boto3
from PIL import Image, ImageDraw, ImageFont
import os
import argparse

def process_pii_detections(jsonl_file, output_dir):
    s3_client = boto3.client('s3')
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    with open(jsonl_file, 'r') as f:
        for line in f:
            data = json.loads(line.strip())
            
            # Check if result has bounding box
            if not data.get('pii_bounding_box'):
                continue
                
            bucket = data['bucket']
            object_key = data['object_key']
            
            # Download image from S3
            local_filename = object_key.split('/')[-1]
            s3_client.download_file(bucket, object_key, local_filename)
            
            # Load image and draw bounding boxes
            image_pil = Image.open(local_filename)
            draw = ImageDraw.Draw(image_pil)
            w, h = image_pil.size
            
            # Try to load a font, fallback to default if not available
            try:
                font = ImageFont.truetype("/System/Library/Fonts/Arial.ttf", 16)
            except:
                font = ImageFont.load_default()
            
            # Draw bounding boxes for each PII category
            for category, bboxes in data['pii_bounding_box'].items():
                for bbox in bboxes:
                    x1, y1, x2, y2 = bbox
                    if x1 >= x2 or y1 >= y2:
                        continue
                    
                    # Convert normalized coordinates to pixel coordinates
                    x1 = x1 / 1000 * w
                    x2 = x2 / 1000 * w
                    y1 = y1 / 1000 * h
                    y2 = y2 / 1000 * h
                    
                    # Draw bounding box
                    draw.rectangle([x1, y1, x2, y2], outline="red", width=2)
                    
                    # Draw label
                    draw.text((x1, y1-20), category, fill="red", font=font)
            
            # Save image with bounding boxes
            output_filename = os.path.join(output_dir, f"{os.path.splitext(local_filename)[0]}_boundingbox{os.path.splitext(local_filename)[1]}")
            image_pil.save(output_filename)
            
            # Clean up downloaded file
            os.remove(local_filename)
            
            print(f"Processed {object_key} -> {output_filename}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process PII detections and draw bounding boxes on images')
    parser.add_argument('--s3-pii-result', default='pii-detect-s3.jsonl', help='Path to the JSONL file containing PII detection results (default: pii-detect-s3.jsonl)')
    parser.add_argument('--output-dir', default='.', help='Directory to save images with bounding boxes (default: current directory)')
    
    args = parser.parse_args()
    process_pii_detections(args.s3_pii_result, args.output_dir)
