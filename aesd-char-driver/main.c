/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"

int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("rrooding");
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    
    struct aesd_dev *dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = dev;

    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    
    size_t read = 0;
    struct aesd_dev *dev = filp->private_data;

    if(mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    while (read < count) {
        size_t entry_off;
        struct aesd_buffer_entry *entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->history, *f_pos, &entry_off);

        if (!entry)
            break;

        size_t to_copy = min(entry->size - entry_off, count - read);
        if (copy_to_user(buf + read, entry->buffptr + entry_off, to_copy)) {
            retval = -EFAULT;
            goto read_done;
        }

        read += to_copy;
        *f_pos += to_copy;
        retval = read;
    }

read_done:
    mutex_unlock(&dev->lock);
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);

    struct aesd_dev *dev = filp->private_data;
    
    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    // Is there an existing buffer to write to?
    if (dev->buffer.buffptr) {
        char *new_buffer = krealloc(dev->buffer.buffptr, dev->buffer.size + count, GFP_KERNEL);

        if (!new_buffer) {
            retval = -ENOMEM;
            goto write_done;
        }

        dev->buffer.buffptr = new_buffer;
    } else {
        dev->buffer.buffptr = kmalloc(count, GFP_KERNEL);
        if (!dev->buffer.buffptr) {
            retval = -ENOMEM;
            goto write_done;
        }
    }

    if (copy_from_user(dev->buffer.buffptr + dev->buffer.size, buf, count)) {
        retval = -EFAULT;
        goto write_done;
    }

    dev->buffer.size += count;
    retval = count;

    // Check for newline
    char *newline = memchr(dev->buffer.buffptr, '\n', dev->buffer.size);
    if (newline) {
        size_t entry_len = newline - dev->buffer.buffptr + 1;
        struct aesd_buffer_entry new = {
            .buffptr = dev->buffer.buffptr,
            .size = entry_len,
        };
        struct aesd_buffer_entry *old = aesd_circular_buffer_add_entry(&dev->history, &new);
        if (old)
            kfree((void *)old->buffptr);

        if (dev->buffer.size > entry_len) {
            size_t rem = dev->buffer.size - entry_len;
            char *keep = kmalloc(rem, GFP_KERNEL);
            if (keep) {
                memcpy(keep, dev->buffer.buffptr + entry_len, rem);
                dev->buffer.buffptr = keep;
                dev->buffer.size = rem;
            } else {
                kfree(dev->buffer.buffptr);
                dev->buffer.buffptr = NULL;
                dev->buffer.size = 0;
            }
        } else {
            dev->buffer.buffptr = NULL;
            dev->buffer.size = 0;
        }
    }

write_done:
    mutex_unlock(&dev->lock);
    return retval;
}
struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    aesd_circular_buffer_init(&aesd_device.history);
    mutex_init(&aesd_device.lock);

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    uint8_t i;
    struct aesd_buffer_entry *entry;

    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.history, i) {
        kfree(entry->buffptr);
    }

    kfree(&aesd_device.buffer.buffptr);

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
