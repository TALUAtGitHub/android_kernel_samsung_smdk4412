/*
 * Copyright (C) 2011 Gokhan Moral
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2 of the License.
 *
 */

#include <linux/platform_device.h>
#include <linux/miscdevice.h>

#define MAX_CURRENT_AC   950
#define MAX_CURRENT_MISC 950
#define MAX_CURRENT_USB  950

int charging_current_ac = 680;
int charging_current_misc = 480;
int charging_current_usb = 480;

static ssize_t
u1_charging_current_show(struct device *dev,
			 struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "AC: %d\nMisc: %d\nUSB: %d\n",
		       charging_current_ac, charging_current_misc,
		       charging_current_usb);
}

static ssize_t
u1_charging_current_store(struct device *dev,
			  struct device_attribute *attr, const char *buf,
			  size_t count)
{
	unsigned int ret = -EINVAL;
	int temp1, temp2, temp3;

	ret = sscanf(buf, "%d %d %d", &temp1, &temp2, &temp3);
	if (ret != 3)
		return -EINVAL;
	else {
		charging_current_ac = (temp1 < MAX_CURRENT_AC) ?
				       temp1 : MAX_CURRENT_AC;
		charging_current_misc = (temp2 < MAX_CURRENT_MISC) ?
					 temp2 : MAX_CURRENT_MISC;
		charging_current_usb = (temp3 < MAX_CURRENT_USB) ?
					temp3 : MAX_CURRENT_USB;
	}

	return count;
}

static DEVICE_ATTR(charging_current, S_IRUGO | S_IWUGO,
		   u1_charging_current_show, u1_charging_current_store);

static struct attribute *charging_current_attributes[] = {
	&dev_attr_charging_current.attr,
	NULL
};

static struct attribute_group charging_current_control_group = {
	.attrs = charging_current_attributes,
};

static struct miscdevice charging_current_control_device = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "charging_current_control",
};

void u1_charging_current_control_init(void)
{
	int err;

	pr_info("%s: initializing charging current control interface\n",
		__func__);

	err = misc_register(&charging_current_control_device);
	if (err)
		pr_err("%s: misc_register failed\n", __func__);

	err = sysfs_create_group(&charging_current_control_device.this_device->kobj,
				 &charging_current_control_group);
	if (err)
		pr_err("%s: failed to create sysfs group for %s\n",
		       __func__, charging_current_control_device.name);
}
