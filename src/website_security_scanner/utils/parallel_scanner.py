#!/usr/bin/env python3
"""
Parallel Scanning Utility

Advanced parallel and sequential scanning capabilities extracted from 
ultra_low_code_scanner.py for performance optimization.

Author: Bachelor Thesis Project - Low-Code Platforms Security Analysis
"""

import time
import concurrent.futures
import threading
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
from datetime import datetime


@dataclass
class ScanTask:
    """Individual scan task definition."""
    id: str
    url: str
    scan_function: Callable
    priority: int = 0
    timeout: int = 30
    retry_count: int = 0
    max_retries: int = 3


@dataclass
class ScanResult:
    """Result of an individual scan task."""
    task_id: str
    success: bool
    result: Any
    error: Optional[str] = None
    execution_time: float = 0.0
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


class ParallelScanner:
    """
    Advanced parallel scanning system with intelligent resource management.
    """
    
    def __init__(self, max_workers: int = 4, timeout: int = 300):
        self.max_workers = max_workers
        self.timeout = timeout
        self.results: Dict[str, ScanResult] = {}
        self.running_tasks: Dict[str, threading.Thread] = {}
        self.completed_tasks: List[str] = []
        self.failed_tasks: List[str] = []
        
        # Thread synchronization locks
        self._results_lock = threading.RLock()
        self._tasks_lock = threading.RLock()
        self._completed_lock = threading.RLock()
        self._failed_lock = threading.RLock()
        
    def parallel_vulnerability_scan(self, url: str, platform_detection: Dict, 
                                  scan_functions: List[Callable]) -> List[Dict]:
        """
        Perform parallel vulnerability scanning using multiple scan functions.
        
        Args:
            url: Target URL
            platform_detection: Platform detection results
            scan_functions: List of scan functions to execute
            
        Returns:
            Combined results from all scan functions
        """
        all_vulnerabilities = []
        futures = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all scan tasks
            for i, scan_func in enumerate(scan_functions):
                future = executor.submit(self._execute_scan_function, scan_func, url, platform_detection)
                futures.append(future)
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(futures, timeout=self.timeout):
                try:
                    result = future.result()
                    if result and isinstance(result, list):
                        all_vulnerabilities.extend(result)
                except Exception as e:
                    print(f"Scan function failed: {e}")
        
        return all_vulnerabilities
    
    def sequential_vulnerability_scan(self, url: str, platform_detection: Dict, 
                                    scan_functions: List[Callable]) -> List[Dict]:
        """
        Perform sequential vulnerability scanning.
        
        Args:
            url: Target URL
            platform_detection: Platform detection results
            scan_functions: List of scan functions to execute
            
        Returns:
            Combined results from all scan functions
        """
        all_vulnerabilities = []
        
        for scan_func in scan_functions:
            try:
                result = self._execute_scan_function(scan_func, url, platform_detection)
                if result and isinstance(result, list):
                    all_vulnerabilities.extend(result)
            except Exception as e:
                print(f"Sequential scan function failed: {e}")
        
        return all_vulnerabilities
    
    def _execute_scan_function(self, scan_func: Callable, url: str, platform_detection: Dict) -> List[Dict]:
        """
        Execute a single scan function safely.
        
        Args:
            scan_func: Function to execute
            url: Target URL
            platform_detection: Platform detection results
            
        Returns:
            Scan results
        """
        try:
            start_time = time.time()
            result = scan_func(url, platform_detection)
            execution_time = time.time() - start_time
            
            print(f"Scan function {scan_func.__name__} completed in {execution_time:.2f}s")
            return result or []
        except Exception as e:
            print(f"Error in scan function {scan_func.__name__}: {e}")
            return []
    
    def execute_tasks(self, tasks: List[ScanTask]) -> Dict[str, ScanResult]:
        """
        Execute a list of scan tasks in parallel.
        
        Args:
            tasks: List of scan tasks to execute
            
        Returns:
            Dictionary of task results
        """
        # Sort tasks by priority (higher priority first)
        sorted_tasks = sorted(tasks, key=lambda x: x.priority, reverse=True)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_task = {}
            for task in sorted_tasks:
                future = executor.submit(self._execute_task, task)
                future_to_task[future] = task
            
            # Collect results
            for future in concurrent.futures.as_completed(future_to_task, timeout=self.timeout):
                task = future_to_task[future]
                try:
                    result = future.result()
                    
                    # Thread-safe result storage
                    with self._results_lock:
                        self.results[task.id] = result
                    
                    if result.success:
                        with self._completed_lock:
                            self.completed_tasks.append(task.id)
                    else:
                        with self._failed_lock:
                            self.failed_tasks.append(task.id)
                        
                except Exception as e:
                    error_result = ScanResult(
                        task_id=task.id,
                        success=False,
                        result=None,
                        error=str(e)
                    )
                    
                    # Thread-safe error storage
                    with self._results_lock:
                        self.results[task.id] = error_result
                    
                    with self._failed_lock:
                        self.failed_tasks.append(task.id)
        
        return self.results
    
    def _execute_task(self, task: ScanTask) -> ScanResult:
        """
        Execute a single scan task with iterative retry logic.
        
        Args:
            task: Task to execute
            
        Returns:
            Task result
        """
        start_time = time.time()
        
        # Iterative retry approach to prevent stack overflow
        while True:
            try:
                result = task.scan_function(task.url)
                execution_time = time.time() - start_time
                
                return ScanResult(
                    task_id=task.id,
                    success=True,
                    result=result,
                    execution_time=execution_time
                )
                
            except Exception as e:
                execution_time = time.time() - start_time
                
                # Check if we should retry
                if task.retry_count < task.max_retries:
                    task.retry_count += 1
                    print(f"Retrying task {task.id} (attempt {task.retry_count})")
                    # Add small delay before retry
                    time.sleep(0.5 * task.retry_count)
                    continue  # Try again
                
                # Max retries reached, return failure
                return ScanResult(
                    task_id=task.id,
                    success=False,
                    result=None,
                    error=str(e),
                    execution_time=execution_time
                )
    
    def get_execution_summary(self) -> Dict[str, Any]:
        """
        Get summary of execution results.
        
        Returns:
            Execution summary
        """
        total_tasks = len(self.results)
        successful_tasks = len(self.completed_tasks)
        failed_tasks = len(self.failed_tasks)
        
        total_time = sum(result.execution_time for result in self.results.values())
        avg_time = total_time / total_tasks if total_tasks > 0 else 0
        
        return {
            'total_tasks': total_tasks,
            'successful_tasks': successful_tasks,
            'failed_tasks': failed_tasks,
            'success_rate': (successful_tasks / total_tasks * 100) if total_tasks > 0 else 0,
            'total_execution_time': total_time,
            'average_execution_time': avg_time,
            'max_workers': self.max_workers
        }
    
    def clear_results(self):
        """Clear all results and reset state in a thread-safe manner."""
        with self._results_lock:
            self.results.clear()
        
        with self._completed_lock:
            self.completed_tasks.clear()
        
        with self._failed_lock:
            self.failed_tasks.clear()
        
        with self._tasks_lock:
            self.running_tasks.clear()


class ScanOptimizer:
    """
    Scan optimization utilities for performance tuning.
    """
    
    @staticmethod
    def optimize_scan_order(scan_functions: List[Callable], url: str) -> List[Callable]:
        """
        Optimize the order of scan functions based on historical performance.
        
        Args:
            scan_functions: List of scan functions
            url: Target URL
            
        Returns:
            Optimized order of scan functions
        """
        # Simple optimization: put faster, more likely to succeed functions first
        priority_functions = {
            'security_headers_scan': 10,
            'ssl_analysis': 9,
            'content_analysis': 8,
            'vulnerability_scan': 7,
            'platform_detection': 6,
            'deep_scan': 5
        }
        
        def get_priority(func):
            func_name = func.__name__.lower()
            for pattern, priority in priority_functions.items():
                if pattern in func_name:
                    return priority
            return 0
        
        return sorted(scan_functions, key=get_priority, reverse=True)
    
    @staticmethod
    def calculate_optimal_workers(url_count: int, complexity: str = 'medium') -> int:
        """
        Calculate optimal number of workers based on URL count and complexity.
        
        Args:
            url_count: Number of URLs to scan
            complexity: Scan complexity ('low', 'medium', 'high')
            
        Returns:
            Optimal number of workers
        """
        complexity_multipliers = {
            'low': 1.5,
            'medium': 1.0,
            'high': 0.5
        }
        
        multiplier = complexity_multipliers.get(complexity, 1.0)
        optimal = min(int(url_count * multiplier), 20)  # Cap at 20 workers
        
        return max(optimal, 1)  # At least 1 worker
    
    @staticmethod
    def estimate_scan_time(url_count: int, complexity: str = 'medium') -> float:
        """
        Estimate total scan time in seconds.
        
        Args:
            url_count: Number of URLs to scan
            complexity: Scan complexity
            
        Returns:
            Estimated time in seconds
        """
        base_times = {
            'low': 5,
            'medium': 15,
            'high': 30
        }
        
        base_time = base_times.get(complexity, 15)
        return url_count * base_time


# Convenience functions
def create_parallel_scan(url: str, scan_functions: List[Callable], 
                        max_workers: int = 4) -> List[Dict]:
    """
    Convenience function for parallel scanning.
    
    Args:
        url: Target URL
        scan_functions: List of scan functions
        max_workers: Maximum number of workers
        
    Returns:
        Combined scan results
    """
    scanner = ParallelScanner(max_workers=max_workers)
    platform_detection = {'platform': 'unknown'}  # Basic detection
    
    return scanner.parallel_vulnerability_scan(url, platform_detection, scan_functions)


def create_sequential_scan(url: str, scan_functions: List[Callable]) -> List[Dict]:
    """
    Convenience function for sequential scanning.
    
    Args:
        url: Target URL
        scan_functions: List of scan functions
        
    Returns:
        Combined scan results
    """
    scanner = ParallelScanner()
    platform_detection = {'platform': 'unknown'}  # Basic detection
    
    return scanner.sequential_vulnerability_scan(url, platform_detection, scan_functions)
