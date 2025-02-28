from concurrent.futures import ThreadPoolExecutor, as_completed


def get_batches(dataset:list, n_batches:int) -> list[list]:
    return (dataset[i:i+n_batches] for i in range(0, len(dataset), n_batches))


def multi_thread_pool(func, arg_list: list[tuple], n_threads: int) -> list:
    results = []
    with ThreadPoolExecutor(max_workers=n_threads) as executor:
        futures = [executor.submit(func, *args) for args in arg_list]
        for future in as_completed(futures):
            results.append(future.result())
    return results
