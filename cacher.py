#!/usr/bin/python
""" This module handles caching function results. It doesn't quite work for class methods. At best, they'll have name collisions and won't be persistent between runs. """

try:
	import cPickle as pickle
except Exception:
	import pickle

import os
import logging

l = logging.getLogger("cacher")

basedir = "cached"
subdir = ""
dir_stack = [ ]

saved_data = { }
locked_data = { }
changed_data = { }

saved_data[""] = { }
locked_data[""] = 0
changed_data[""] = { }

####################
### subdir stuff ###
####################

def push_subdir(new_subdir, save_current=True):
	global subdir

	dir_stack.append(subdir)
	set_subdir(new_subdir, save_current)

def pop_subdir(save_current=True):
	set_subdir(dir_stack.pop(), save_current)

def set_subdir(new_subdir, save_current=True):
	global subdir

	if save_current:
		save_subdir(subdir)
		flush()

	if new_subdir not in saved_data:
		saved_data[new_subdir] = { }

	if new_subdir not in changed_data:
		changed_data[new_subdir] = { }

	if new_subdir not in locked_data:
		locked_data[new_subdir] = 0

	subdir = new_subdir

#################
### save/load ###
#################

def save_subdir(d):
	if d not in changed_data:
		return

	for f in changed_data[d].keys():
		save_entry(d, f)

def save():
	for d in changed_data:
		save_subdir(d)

def save_entry(d, name):
	global basedir
	fullpath = basedir + "/" + subdir + "/" + name + ".p"

	try:
		l.debug("Making directory: %s" % os.path.dirname(fullpath))
		os.makedirs(os.path.dirname(fullpath))
	except OSError:
		pass

	if name in changed_data[d].keys():
		l.info("Saving %d entries to %s" % (len(saved_data[d][name]), fullpath))
		pickle.dump(saved_data[d][name], open(fullpath, "w"))
		del changed_data[d][name]

def load(name):
	global subdir
	load_entry(subdir, name)

def load_entry(d, name):
	global basedir
	fullpath = basedir + "/" + subdir + "/" + name + ".p"

	try:
		l.info("Loading " + fullpath)

		saved_data[d][name] = pickle.load(open(fullpath, "r"))
		l.info(".... %d loaded" % len(saved_data[d][name]))
	except Exception, e:
		l.info(".... exception: " + str(e) + "! Creating empty dict.")
		saved_data[d][name] = { }

def flush():
	locked_set = set([ d for d in locked_data if locked_data[d] > 0 ])
	for d in (set(saved_data.keys()) | set(changed_data.keys())) - locked_set:
		flush_subdir(d)

def flush_subdir(d):
	save_subdir(d)
	discard_subdir(d)

def discard():
	locked_set = set([ d for d in locked_data if locked_data[d] > 0 ])
	for d in (set(saved_data.keys()) | set(changed_data.keys())) - locked_set:
		discard_subdir(d)

def discard_subdir(d):
	if d in saved_data:
		del saved_data[d]

	if d in changed_data:
		del changed_data[d]

	# this will cause key errors at unlock
	#if d in locked_data:
	#	del locked_data[d]

def discard_entry(d, name):
	l.debug("Discarding %s from %s", name, d)
	if d in saved_data and name in saved_data[d]:
		del saved_data[d][name]

	if d in changed_data and name in changed_data[d]:
		del changed_data[d][name]

# locking stuff, subdir level for now
def lock_entry(d, n):
	lock_subdir(d)

def lock_subdir(d):
	if d not in locked_data:
		locked_data[d] = 0

	locked_data[d] += 1

def unlock_entry(d, n):
	unlock_subdir(d)

def unlock_subdir(d):
	locked_data[d] -= 1

def check_locked_dir(d):
	return d in locked_data and locked_data[d] > 0

def check_locked_entry(d, n):
	return check_locked_dir(d)

#############################
### caching functionality ###
#############################

# builds the cache key of a function
def get_cache_name(f, dir_name, module_name, function_name, version_name):
	name = ""

	if dir_name is not None:
		name += dir_name + "/"

	# first comes the module name
	if module_name is not None:
		name += module_name
	else:
		name += f.__module__

	name += "."

	if function_name is not None:
		name += function_name
	else:
		name += f.__name__

	if version_name is None:
		name += "%" + str(hash(f.__code__))
	elif version_name != "":
		name += "%" + version_name

	return name

# returns the dict of cache values
def get_saved_dict(name):
	if subdir not in saved_data:
		saved_data[subdir] = { }

	if name not in saved_data[subdir]:
		load_entry(subdir, name)

	return saved_data[subdir][name]

# sets a saved dictionary
def set_saved_dict(name, new_dict):
	if subdir not in saved_data:
		saved_data[subdir] = { }

	saved_data[subdir][name] = new_dict
	return new_dict

# marks a cache as changed
def mark_cache_changed(name):
	if subdir not in changed_data:
		changed_data[subdir] = { }

	changed_data[subdir][name] = True

# retrieves an entry from the cache
# returns a tuple (success, val)
# success is a boolean of whether or
# not the value was retrieved, and
# val is the value
def get_from_cache(name, key):
	saved_dict = get_saved_dict(name)

	if key in saved_dict:
		l.debug("cached: %s %s" % (str(name), str(key)))
		return (True, saved_dict[key])
	else:
		return (False, None)

def wrapper(f, cache_name, each, disk, autosave, autodiscard):
	###
	### Internal helper functions for the various wrapped functions
	###

	# get the final keys for the cache
	def f_get_keys(*args, **kwargs):
		key = (str(args), str(kwargs))
		if each:
			f_name = cache_name + "_" + str(hash(key))
		else:
			f_name = cache_name

		return f_name, key

	# this is called when a cache dict is updated
	def f_update(f_name):
		global subdir

		if disk:
			mark_cache_changed(f_name)

		if autosave:
			save_entry(subdir, f_name)

		if autodiscard:
			discard_entry(subdir, f_name)

	# set a cache value
	def f_set(f_name, key, retval):
		get_saved_dict(f_name)[key] = retval
		f_update(f_name)

	###
	### User-accessible functions
	###

	# returns the cache dictionary for direct mischief
	def f_dict(*args, **kwargs):
		f_name, key = f_get_keys(*args, **kwargs)
		return get_saved_dict(f_name)

	# check if a value is in the cache
	def f_check(*args, **kwargs):
		f_name, key = f_get_keys(*args, **kwargs)
		in_cache, retval = get_from_cache(f_name, key)
		if autodiscard:
			discard_entry(subdir, f_name)
		return in_cache

	# remove a value from the cache
	def f_remove(*args, **kwargs):
		f_name, key = f_get_keys(*args, **kwargs)
		in_cache, retval = get_from_cache(f_name, key)
		if in_cache:
			del get_saved_dict(f_name)[key]
			f_update(f_name)

	# Replaces the cache with a blank one. Supports "each" caches by taking arguments
	def f_clear(*args, **kwargs):
		f_name, key = f_get_keys(*args, **kwargs)
		set_saved_dict(f_name, {})
		f_update(f_name)

	# Discards the cache. Supports "each" caches by taking arguments
	def f_discard(*args, **kwargs):
		global subdir
		f_name, key = f_get_keys(*args, **kwargs)
		discard_entry(subdir, f_name)

	# returns a function that sets a cache entry for specific arguments
	# the returned function takes a value to set the cache to.
	def f_setter(*args, **kwargs):
		f_name, key = f_get_keys(*args, **kwargs)
		def setter(retval):
			f_set(f_name, key, retval)
			return retval
		return setter

	# the wrapped function itself
	def f_wrapped(*args, **kwargs):
		global subdir

		f_name, key = f_get_keys(*args, **kwargs)
		in_cache, retval = get_from_cache(f_name, key)

		if in_cache:
			if autodiscard:
				discard_entry(subdir, f_name)

			return retval
		else:
			l.info("not cached: %s %s" % (str(f_name), str(key)))

			lock_entry(subdir, f_name)
			try:
				retval = f(*args, **kwargs)
				f_set(f_name, key, retval)
				return retval
			finally:
				unlock_entry(subdir, f_name)

	# saves a cache (supports each if given arguments)
	def f_save(*args, **kwargs):
		global subdir
		f_name, key = f_get_keys(*args, **kwargs)
		save_entry(subdir, f_name)

	# loads a cache (supports each if given arguments)
	def f_load(*args, **kwargs):
		global subdir
		f_name, key = f_get_keys(*args, **kwargs)
		load_entry(subdir, f_name)

	f_wrapped.__name__ = f.__name__
	f_wrapped.__doc__ = f.__doc__
	f_wrapped.__str__ = f.__str__
	setattr(f_wrapped, "cache_orig", f)
	setattr(f_wrapped, "cache_check", f_check)
	setattr(f_wrapped, "cache_clear", f_clear)
	setattr(f_wrapped, "cache_remove", f_remove)
	setattr(f_wrapped, "cache_setter", f_setter)
	setattr(f_wrapped, "cache_discard", f_discard)
	setattr(f_wrapped, "cache_save", f_save)
	setattr(f_wrapped, "cache_load", f_load)
	setattr(f_wrapped, "cache_dict", f_dict)

	setattr(f_wrapped, "__cache_name", cache_name)
	setattr(f_wrapped, "__cache_set", f_set)
	setattr(f_wrapped, "__cache_get_keys", f_get_keys)

	return f_wrapped

# This is the decorator that causes the function decorated to be wrapped in a cacher.
# The function generates a filename for the function. Several options influence this.
#
# Cache filename options:
#
#   dir_name - the directory (under the current subdir) to put the file in. Default: ''
#   module_name - the name of the module. Default: function.__module__
#   function_name - the name of the function. Default: function.__name__
#   version_name - the version of the function. Default: str(hash(f.__code__))
#   each - if this is True, the arguments to the function are cached and included in the filename
#
# Other options:
#
#   disk - save the cache out to disk. Default: True
#   autosave - autosave the cache to disk after each added value. Useless without disk. Default: False
#   autodiscard - discard the cache after every use. Useful with 'each' and big cached things. Default: False
#
# The autosave and autodiscard options might do unexpected things, especially when recursion is concerned, so be careful!
#
# The wrapped function will have several useful attributes:
#
#    cache_orig - the original (unwrapped function) for direct access
#    cache_dict - returns the cache dictionary. Note that this doesn't work well with autosave and autodiscard.
#    cache_check - checks whether a set of arguments are in the cache
#    cache_setter - returns a setter function for specific arguments that can be used set the cache
#    cache_remove - removes an entry from the cache
#    cache_discard - discards the cache (allowing it to be reloaded at the next call)
#    cache_clear - clears the cache (replaces it with an empty dictionary)
#    cache_save - saves the cache to disk
#    cache_load - loads the cache from disk
#
# These functions generally take an *args and **kwargs (of the wrapped function) as arguments.
def wrap(dir_name = None, module_name = None, function_name = None, version_name = None, each = False, disk = True, autosave = False, autodiscard = False):
	def dec_wrap(f):
		# build the name
		cache_name = get_cache_name(f, dir_name, module_name, function_name, version_name)
		# wrap it
		return wrapper(f, cache_name, each, disk, autosave, autodiscard)
	return dec_wrap
