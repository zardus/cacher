#!/usr/bin/python
""" This module handles caching function results. It doesn't quite work for class methods. At best, they'll have name collisions and won't be persistent between runs. """

try:
	import cPickle as pickle
	pickle # this is here to shut up syntastic
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

#################
### save/load ###
#################

def push_subdir(new_subdir):
	global subdir

	dir_stack.append(subdir)
	set_subdir(new_subdir)

def pop_subdir():
	set_subdir(dir_stack.pop())

def set_subdir(new_subdir):
	global subdir

	save_subdir(subdir)
	flush()

	if new_subdir not in saved_data:
		saved_data[new_subdir] = { }

	if new_subdir not in changed_data:
		changed_data[new_subdir] = { }

	if new_subdir not in locked_data:
		locked_data[new_subdir] = 0

	subdir = new_subdir

def save_subdir(d):
	if d not in changed_data:
		return

	for f in changed_data[d].keys():
		save_one(d, f)

def save():
	for d in changed_data:
		save_subdir(d)

def save_one(d, f):
	global basedir

	try:
		os.makedirs(basedir + "/" + subdir)
	except Exception:
		pass

	if f in changed_data[d].keys():
		l.info("Saving %d entries of %s to %s/%s" % (len(saved_data[d][f]), f, basedir, subdir))
		pickle.dump(saved_data[d][f], open(basedir + "/" + d + "/" + f + ".p", "w"))
		del changed_data[d][f]

def load(name):
	global subdir
	load_subdir(subdir, name)

def load_subdir(d, name):
	global basedir

	try:
		l.info("Loading " + name + " from " + basedir + "/" + d + "... ")

		saved_data[d][name] = pickle.load(open(basedir + "/" + d + "/" + name + ".p", "r"))
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

	if d in saved_data:
		del saved_data[d]

	if d in changed_data:
		del changed_data[d]

	if d in locked_data:
		del locked_data[d]

#############################
### caching functionality ###
#############################

def wrapper(f, n, m, each, disk, versioned, cacheid, autosave):
	# build the name
	if cacheid == None:
		cacheid = (str(f.__cacheid__) if hasattr(f, '__cacheid__') else str(hash(f.__code__)))
	name = (m if m != "" else f.__module__) + "." + (n if n != "" else f.__name__) + ("%" + cacheid if versioned else "")

	def f_cached(*args, **kwargs):
		if subdir not in saved_data:
			saved_data[subdir] = { }

		key = name + ("_" + str(hash(str(hash((str(args), str(kwargs)))))) if each else "")
		if key not in saved_data[subdir]:
			load_subdir(subdir, key)

		if (str(args), str(kwargs)) in saved_data[subdir][key]:
			l.debug("cached: %s %s %s" % (str(key), str(args), str(kwargs)))
			return saved_data[subdir][key][str(args), str(kwargs)]
		else:
			l.debug("not cached: %s %s %s" % (str(key), str(args), str(kwargs)))

			locked_data[subdir] += 1
			try:
				tmp = f(*args, **kwargs)
				saved_data[subdir][key][(str(args), str(kwargs))] = tmp

				if disk:
					changed_data[subdir][key] = True

				if autosave:
					save_subdir(subdir, key)

				return tmp
			finally:
				locked_data[subdir] -= 1

	f_cached.__name__ = f.__name__
	f_cached.__doc__ = f.__doc__
	f_cached.__str__ = f.__str__
	setattr(f_cached, "wrapped_func", f)

	return f_cached

def wrap(name = "", module_id = "", each = False, disk = True, versioned = True, cacheid = None, autosave = False):
	def dec_wrap(f):
		return wrapper(f, name, module_id, each, disk, versioned, cacheid, autosave)
	return dec_wrap
