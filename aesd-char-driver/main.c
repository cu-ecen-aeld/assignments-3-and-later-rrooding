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
#include "aesd-circular-buffer.h"
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("rrooding"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    filp->private_data = &aesd_device;
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    struct aesd_dev *dev = filp->private_data;
    struct aesd_buffer_entry *entry;
    size_t entry_offset;
    if (!buf || count == 0)
        return -EINVAL;

    mutex_lock(&dev->lock);

    entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->buffer, *f_pos, &entry_offset);
    if (!entry) {
        retval = 0;
        goto out;
    }

    size_t bytes_available = entry->size - entry_offset;
    size_t bytes_to_copy = min(count, bytes_available);

    if (copy_to_user(buf, entry->buffptr + entry_offset, bytes_to_copy)) {
        retval = -EFAULT;
        goto out;
    }

    *f_pos += bytes_to_copy;
    retval = bytes_to_copy;

    out:
    mutex_unlock(&dev->lock);
    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    struct aesd_dev *dev = filp->private_data;
    ssize_t retval = count;
    char *new_buf, *write_buf;
    size_t new_size;
    struct aesd_buffer_entry new_entry;

    PDEBUG("write %zu bytes with offset %lld", count, *f_pos);

    if (!buf || count == 0)
        return -EINVAL;

    write_buf = kmalloc(count, GFP_KERNEL);
    if (!write_buf)
        return -ENOMEM;

    if (copy_from_user(write_buf, buf, count)) {
        kfree(write_buf);
        return -EFAULT;
    }

    mutex_lock(&dev->lock);

    new_size = dev->partial_size + count;
    new_buf = kmalloc(new_size, GFP_KERNEL);
    if (!new_buf) {
        kfree(write_buf);
        retval = -ENOMEM;
        goto out;
    }

    if (dev->partial) {
        memcpy(new_buf, dev->partial, dev->partial_size);
        kfree(dev->partial);
    }
    memcpy(new_buf + dev->partial_size, write_buf, count);
    kfree(write_buf);

    dev->partial = new_buf;
    dev->partial_size = new_size;

    if (memchr(dev->partial, '\n', dev->partial_size)) {
        new_entry.buffptr = dev->partial;
        new_entry.size = dev->partial_size;

        const char *discard = aesd_circular_buffer_add_entry(&dev->buffer, &new_entry);
        if (discard) {
            kfree(discard);
        }

        dev->partial = NULL;
        dev->partial_size = 0;
    }

out:
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

    aesd_circular_buffer_init(&aesd_device.buffer);
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

    uint8_t index;
    struct aesd_buffer_entry *entry;
    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.buffer, index) {
    kfree(entry->buffptr);
    }

    if (aesd_device.partial)
        kfree(aesd_device.partial);

    mutex_destroy(&aesd_device.lock);
    unregister_chrdev_region(devno, 1);
}

module_init(aesd_init_module);
module_exit(aesd_cleanup_module);