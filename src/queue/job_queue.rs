use tokio::sync::mpsc;
use tracing::{debug, info};
use anyhow::{Context, Result};

use crate::models::job::Job;

/// Central job queue for distributing work to workers
#[derive(Clone)]
pub struct JobQueue {
    sender: mpsc::UnboundedSender<Job>,
}

impl JobQueue {
    pub fn new() -> (Self, mpsc::UnboundedReceiver<Job>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        (Self { sender }, receiver)
    }

    /// Submit a job to the queue
    pub fn submit(&self, job: Job) -> Result<()> {
        let job_type = match &job {
            Job::Discovery(_) => "Discovery",
            Job::PortScan(_) => "PortScan",
            Job::InfoGather(_) => "InfoGather",
            Job::VulnScan(_) => "VulnScan",
        };

        debug!("Submitting {} job to queue", job_type);

        self.sender
            .send(job)
            .context("Failed to submit job to queue")
    }

    /// Submit multiple jobs at once
    pub fn submit_batch(&self, jobs: Vec<Job>) -> Result<()> {
        info!("Submitting batch of {} jobs", jobs.len());
        for job in jobs {
            self.submit(job)?;
        }
        Ok(())
    }
}

impl Default for JobQueue {
    fn default() -> Self {
        Self::new().0
    }
}
