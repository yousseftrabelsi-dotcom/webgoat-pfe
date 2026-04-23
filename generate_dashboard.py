import json
import matplotlib.pyplot as plt
import numpy as np

# ... other functions ...

def fig_sca(data):
    # Filter out zero-value severities
    filtered_data = [d for d in data if d['severity'] > 0]
    # ... plot logic using filtered_data ...


def fig_falco(data):
    # Handle empty data
    if not data:
        print('No data to display')
        return
    # ... plotting logic ...

# ... existing code ...

# Update layout spacing in the dashboard
# ... code ...

# Fix trend injection vulnerability
# ... code ...

# end of file
