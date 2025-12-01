import threading
import time
from client import Client


NUM_CLIENTS = 20

def run_single_client(client_id):
    print(f"Starting Client {client_id}")
    try:
        my_client = Client()
        my_client.connect_to_server(thread_id=client_id)
    except Exception as e:
        print(f"Client {client_id} encountered an error: {e}")
    finally:
        print(f"Client {client_id} finished")

if __name__ == "__main__":
    client_threads = []
    print(f"Starting {NUM_CLIENTS} simultaneous client threads")
    
    start_time = time.time()

    for i in range(1, NUM_CLIENTS + 1):
        t = threading.Thread(target=run_single_client, args=(i,))
        client_threads.append(t)
        t.start()

    for t in client_threads:
        t.join()

    end_time = time.time()
    
    print(f"All {NUM_CLIENTS} clients finished their session.")
    print(f"Total execution time: {end_time - start_time:.2f} seconds.")