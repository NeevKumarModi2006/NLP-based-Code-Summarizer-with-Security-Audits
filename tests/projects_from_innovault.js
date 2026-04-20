/**
 * Project Routes
 * ───────────────
 * All CRUD operations for Projects, Reviews, and Bookmarks.
 *
 * Infrastructure integrations:
 *   - Redis caching on read-heavy GET endpoints
 *   - Cache invalidation on all mutation endpoints
 *   - Kafka event publishing on all mutation endpoints (fire-and-forget)
 *
 * HIGH COHESION: Each route handler focuses on a single operation.
 * LOW COUPLING:  Cache, events, and auth are injected as middleware/services.
 */

const router = require('express').Router();
const mongoose = require('mongoose');
const Project = require('../models/Project');
const User = require('../models/User');
const Review = require('../models/Review');
const ProjectView = require('../models/ProjectView');
const verify = require('../middleware/verifyToken');

// ── Infrastructure Services ────────────────────────────────
const cacheMiddleware = require('../middleware/cache');
const { clearCacheByPrefix } = require('../services/cacheService');
const { publishEvent } = require('../events/producer');

// Cache key prefixes (centralized for consistency)
const CACHE_PREFIX = {
    LIST: 'projects:list',
    DETAIL: 'projects:detail',
    REVIEWS: 'projects:reviews',
};

/**
 * Invalidate all project-related caches.
 * Called after any mutation (create, update, delete, review).
 */
async function invalidateProjectCaches(projectId) {
    await Promise.all([
        clearCacheByPrefix(CACHE_PREFIX.LIST),
        clearCacheByPrefix(`${CACHE_PREFIX.DETAIL}:${projectId}`),
        clearCacheByPrefix(`${CACHE_PREFIX.REVIEWS}:${projectId}`),
    ]);
}


// ═══════════════════════════════════════════════════════════
// GET All Projects — Paginated, Filtered, Sorted (CACHED)
// ═══════════════════════════════════════════════════════════
router.get('/', cacheMiddleware(CACHE_PREFIX.LIST), async (req, res) => {
    try {
        const { search, techStack, sort, page = 1, limit = 20 } = req.query;
        let query = { status: 'active' };

        if (search) {
            query.$or = [
                { title: { $regex: search, $options: 'i' } },
                { shortDescription: { $regex: search, $options: 'i' } },
                { techStack: { $regex: search, $options: 'i' } }
            ];
        }

        if (techStack) {
            const regexTags = techStack.split(',').map(t => new RegExp('^' + t.trim() + '$', 'i'));
            query.techStack = { $in: regexTags };
        }

        let sortOption = { createdAt: -1 };
        if (sort === 'rating') sortOption = { averageRating: -1 };
        if (sort === 'views') sortOption = { views: -1 };

        const skip = (parseInt(page) - 1) * parseInt(limit);
        const total = await Project.countDocuments(query);

        // Projection: omit large detailedDescription field on list view
        const projects = await Project.find(query)
            .select('-detailedDescription')
            .populate('owner', 'username role profilePicture')
            .sort(sortOption)
            .skip(skip)
            .limit(parseInt(limit));

        res.json({
            projects,
            pagination: {
                total,
                page: parseInt(page),
                limit: parseInt(limit),
                totalPages: Math.ceil(total / parseInt(limit))
            }
        });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});


// ═══════════════════════════════════════════════════════════
// GET Single Project (CACHED per project ID)
// ═══════════════════════════════════════════════════════════
router.get('/:id', async (req, res, next) => {
    // Dynamic cache key per project — skip cache middleware for
    // invalid IDs to avoid polluting the cache
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
        return res.status(400).json({ message: 'Invalid project ID.' });
    }
    // Apply cache middleware dynamically with project-specific prefix
    cacheMiddleware(`${CACHE_PREFIX.DETAIL}:${req.params.id}`)(req, res, next);
}, async (req, res) => {
    try {
        const project = await Project.findById(req.params.id)
            .populate('owner', 'username role profilePicture bio');

        if (!project) return res.status(404).json({ message: 'Project not found' });

        res.json(project);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});


// ═══════════════════════════════════════════════════════════
// PUT Increment View (not cached — mutation)
// ═══════════════════════════════════════════════════════════
router.put('/:id/view', async (req, res) => {
    try {
        const viewerId = req.body.viewerId;
        const project = await Project.findById(req.params.id);
        
        if (!project) return res.status(404).json({ message: 'Project not found' });

        if (viewerId && project.owner && String(project.owner) === String(viewerId)) {
            return res.json({ success: true, ignored: true });
        }

        const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'anonymous';
        const identifier = (viewerId && viewerId !== 'undefined' && viewerId !== 'null') ? String(viewerId) : clientIp;

        const existingView = await ProjectView.findOne({
            projectId: project._id,
            viewerIdentifier: identifier
        });

        if (existingView) {
            return res.json({ success: true, alreadyViewed: true });
        }

        await ProjectView.create({
            projectId: project._id,
            viewerIdentifier: identifier
        });

        await Project.findByIdAndUpdate(req.params.id, { $inc: { views: 1 } });

        // Invalidate detail cache (view count changed)
        invalidateProjectCaches(req.params.id).catch(() => {});

        res.json({ success: true });
    } catch (err) {
        if (err.code === 11000) {
            return res.json({ success: true, alreadyViewed: true });
        }
        res.status(500).json({ message: err.message });
    }
});


// ═══════════════════════════════════════════════════════════
// Upload middleware + rate limiter
// ═══════════════════════════════════════════════════════════
const upload = require('../middleware/upload');
const rateLimit = require('express-rate-limit');

const projectSubmitLimiter = rateLimit({
    windowMs: 24 * 60 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false,
    validate: { xForwardedForHeader: false, default: false },
    message: { message: 'Daily limit of 20 project submissions/edits reached. Please try again tomorrow.' }
});


// ═══════════════════════════════════════════════════════════
// POST Create Project (Verified Only)
// ═══════════════════════════════════════════════════════════
router.post('/', verify, projectSubmitLimiter, upload.single('logo'), async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        if (user.role !== 'VERIFIED' && user.role !== 'ADMIN') {
            return res.status(403).json({ message: 'Only verified NITW users can post projects.' });
        }

        let parsedTechStack = req.body.techStack;
        if (typeof parsedTechStack === 'string') {
            parsedTechStack = parsedTechStack.split(',').map(t => t.trim()).filter(t => t);
        }

        // Determine logo identifier:
        // Cloudinary → req.file.filename = public_id (e.g. "innovault/logos/abc123")
        // Local disk → req.file.filename = "logo-1234567890.png"
        const logoIdentifier = req.file ? req.file.filename : 'default-logo.png';

        const project = new Project({
            ...req.body,
            techStack: parsedTechStack,
            owner: req.user._id,
            logoUrl: logoIdentifier
        });

        const savedProject = await project.save();

        // ── Background: Cache + Events ─────────────────────
        invalidateProjectCaches(savedProject._id).catch(() => {});
        publishEvent('PROJECT_CREATED', {
            projectId: savedProject._id,
            title: savedProject.title,
            owner: req.user._id,
        }).catch(() => {});

        res.json(savedProject);
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});


// ═══════════════════════════════════════════════════════════
// PUT Edit Project
// ═══════════════════════════════════════════════════════════
router.put('/:id', verify, projectSubmitLimiter, upload.single('logo'), async (req, res) => {
    try {
        const project = await Project.findById(req.params.id);
        if (!project) return res.status(404).json({ message: 'Project not found.' });

        if (project.owner.toString() !== req.user._id) {
            return res.status(403).json({ message: 'You are not authorized to edit this project.' });
        }

        let parsedTechStack = req.body.techStack;
        if (typeof parsedTechStack === 'string') {
            parsedTechStack = parsedTechStack.split(',').map(t => t.trim()).filter(t => t);
        }

        const updatedData = {
            ...req.body,
            techStack: parsedTechStack || project.techStack
        };

        if (req.file) {
            updatedData.logoUrl = req.file.filename;
        }

        const updatedProject = await Project.findByIdAndUpdate(
            req.params.id,
            { $set: updatedData },
            { new: true }
        );

        // ── Background: Cache + Events ─────────────────────
        invalidateProjectCaches(req.params.id).catch(() => {});
        publishEvent('PROJECT_UPDATED', {
            projectId: req.params.id,
            title: updatedProject.title,
            updatedBy: req.user._id,
        }).catch(() => {});

        res.json(updatedProject);
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});


// ═══════════════════════════════════════════════════════════
// DELETE Project
// ═══════════════════════════════════════════════════════════
router.delete('/:id', verify, async (req, res) => {
    try {
        const project = await Project.findById(req.params.id);
        if (!project) return res.status(404).json({ message: 'Project not found.' });

        if (project.owner.toString() !== req.user._id) {
            return res.status(403).json({ message: 'You are not authorized to delete this project.' });
        }

        await Project.findByIdAndDelete(req.params.id);

        // ── Background: Cache + Events ─────────────────────
        invalidateProjectCaches(req.params.id).catch(() => {});
        publishEvent('PROJECT_DELETED', {
            projectId: req.params.id,
            title: project.title,
            deletedBy: req.user._id,
        }).catch(() => {});

        res.json({ message: 'Project deleted successfully.' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});


// ═══════════════════════════════════════════════════════════
// POST/PUT Review (Upsert Dual Tier Logic)
// ═══════════════════════════════════════════════════════════
router.post('/:id/reviews', verify, async (req, res) => {
    try {
        const { rating, comment, pros, cons } = req.body;
        const projectId = req.params.id;
        const userId = req.user._id;

        const user = await User.findById(userId);
        const projectRecord = await Project.findById(projectId);

        if (!projectRecord) return res.status(404).json({ message: 'Project not found.' });
        if (projectRecord.owner.toString() === userId.toString()) {
            return res.status(403).json({ message: "You cannot review your own project." });
        }

        const isVerifiedRating = user.role === 'VERIFIED';

        let review = await Review.findOne({ user: userId, project: projectId });
        if (review) {
            review.rating = rating;
            review.comment = comment;
            review.pros = pros;
            review.cons = cons;
            review.isEdited = true;
            review.updatedAt = Date.now();
            await review.save();
        } else {
            review = new Review({
                user: userId,
                project: projectId,
                rating,
                comment,
                pros,
                cons,
                isVerifiedRating
            });
            await review.save();
        }

        // Recalculate Project Ratings (Aggregation)
        const stats = await Review.aggregate([
            { $match: { project: review.project, isDeleted: { $ne: true } } },
            {
                $group: {
                    _id: '$project',
                    avgRating: { $avg: '$rating' },
                    avgVerifiedRating: {
                        $avg: {
                            $cond: [{ $eq: ['$isVerifiedRating', true] }, '$rating', null]
                        }
                    }
                }
            }
        ]);

        if (stats.length > 0) {
            await Project.findByIdAndUpdate(projectId, {
                averageRating: stats[0].avgRating || 0,
                verifiedRating: stats[0].avgVerifiedRating || 0
            });
        }

        // ── Background: Cache + Events ─────────────────────
        invalidateProjectCaches(projectId).catch(() => {});
        publishEvent('REVIEW_ADDED', {
            reviewId: review._id,
            projectId,
            userId,
            rating,
        }).catch(() => {});

        res.json(review);
    } catch (err) {
        res.status(400).json({ message: err.message });
    }
});


// ═══════════════════════════════════════════════════════════
// PUT Report Review
// ═══════════════════════════════════════════════════════════
router.put('/:id/reviews/:reviewId/report', verify, async (req, res) => {
    try {
        const projectId = req.params.id;
        const reviewId = req.params.reviewId;
        const userId = req.user._id;

        const review = await Review.findById(reviewId);
        if (!review) return res.status(404).json({ message: 'Review not found.' });

        if (!review.reportedBy.includes(userId)) {
            review.reportedBy.push(userId);
            
            const threshold = parseInt(process.env.REPORT_THRESHOLD) || 20;
            let newlyDeleted = false;

            if (review.reportedBy.length >= threshold) {
                review.isDeleted = true;
                newlyDeleted = true;
            }

            await review.save();

            if (newlyDeleted) {
                const stats = await Review.aggregate([
                    { $match: { project: new mongoose.Types.ObjectId(projectId), isDeleted: { $ne: true } } },
                    {
                        $group: {
                            _id: '$project',
                            avgRating: { $avg: '$rating' },
                            avgVerifiedRating: {
                                $avg: {
                                    $cond: [{ $eq: ['$isVerifiedRating', true] }, '$rating', null]
                                }
                            }
                        }
                    }
                ]);

                if (stats.length > 0) {
                    await Project.findByIdAndUpdate(projectId, {
                        averageRating: stats[0].avgRating || 0,
                        verifiedRating: stats[0].avgVerifiedRating || 0
                    });
                } else {
                    await Project.findByIdAndUpdate(projectId, {
                        averageRating: 0,
                        verifiedRating: 0
                    });
                }

                // Invalidate cache on auto-deletion
                invalidateProjectCaches(projectId).catch(() => {});
            }
            
            res.json({ message: 'Report submitted successfully.', newlyDeleted });
        } else {
            res.status(400).json({ message: 'You have already reported this review.' });
        }
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});


// ═══════════════════════════════════════════════════════════
// DELETE Review
// ═══════════════════════════════════════════════════════════
router.delete('/:id/reviews', verify, async (req, res) => {
    try {
        const projectId = req.params.id;
        const userId = req.user._id;

        const deletedReview = await Review.findOneAndDelete({ user: userId, project: projectId });
        if (!deletedReview) return res.status(404).json({ message: 'Review not found.' });

        const stats = await Review.aggregate([
            { $match: { project: new mongoose.Types.ObjectId(projectId), isDeleted: { $ne: true } } },
            {
                $group: {
                    _id: '$project',
                    avgRating: { $avg: '$rating' },
                    avgVerifiedRating: {
                        $avg: {
                            $cond: [{ $eq: ['$isVerifiedRating', true] }, '$rating', null]
                        }
                    }
                }
            }
        ]);

        if (stats.length > 0) {
            await Project.findByIdAndUpdate(projectId, {
                averageRating: stats[0].avgRating || 0,
                verifiedRating: stats[0].avgVerifiedRating || 0
            });
        } else {
            await Project.findByIdAndUpdate(projectId, {
                averageRating: 0,
                verifiedRating: 0
            });
        }

        // ── Background: Cache + Events ─────────────────────
        invalidateProjectCaches(projectId).catch(() => {});
        publishEvent('REVIEW_DELETED', {
            reviewId: deletedReview._id,
            projectId,
            userId,
        }).catch(() => {});

        res.json({ message: 'Review deleted successfully.' });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});


// ═══════════════════════════════════════════════════════════
// GET Bookmarked Projects
// ═══════════════════════════════════════════════════════════
router.get('/bookmarked/me', verify, async (req, res) => {
    try {
        const user = await User.findById(req.user._id).populate({
            path: 'bookmarks',
            populate: { path: 'owner', select: 'username role profilePicture' }
        });
        res.json(user.bookmarks || []);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});


// ═══════════════════════════════════════════════════════════
// GET My Review for a Project
// ═══════════════════════════════════════════════════════════
router.get('/:id/my-review', verify, async (req, res) => {
    try {
        const review = await Review.findOne({ project: req.params.id, user: req.user._id })
            .populate('user', 'username role profilePicture');
        res.json(review);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});


// ═══════════════════════════════════════════════════════════
// GET Reviews for a Project (CACHED per project + filters)
// ═══════════════════════════════════════════════════════════
router.get('/:id/reviews', async (req, res, next) => {
    // Dynamic cache key per project
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
        return res.status(400).json({ message: 'Invalid project ID.' });
    }
    cacheMiddleware(`${CACHE_PREFIX.REVIEWS}:${req.params.id}`)(req, res, next);
}, async (req, res) => {
    try {
        const { page = 1, limit = 20, sort, filter } = req.query;
        const projectId = req.params.id;
        let query = { project: projectId, isDeleted: { $ne: true } };

        if (filter === 'verifiedOnly') {
            query.isVerifiedRating = true;
        } else if (filter && filter.startsWith('rating-')) {
            query.rating = parseInt(filter.split('-')[1]);
        }

        let sortOption = { rating: -1, createdAt: -1 };
        if (sort === 'lowest') sortOption = { rating: 1, createdAt: -1 };
        if (sort === 'recent') sortOption = { updatedAt: -1, createdAt: -1 };

        const skip = (parseInt(page) - 1) * parseInt(limit);
        const total = await Review.countDocuments({ project: projectId });
        const filteredTotal = await Review.countDocuments(query);

        const reviews = await Review.find(query)
            .populate('user', 'username role profilePicture')
            .sort(sortOption)
            .skip(skip)
            .limit(parseInt(limit));

        const statsAggregation = await Review.aggregate([
            { $match: { project: new mongoose.Types.ObjectId(projectId), isDeleted: { $ne: true } } },
            {
                $group: {
                    _id: null,
                    totalReviews: { $sum: 1 },
                    totalVerified: { $sum: { $cond: [{ $eq: ['$isVerifiedRating', true] }, 1, 0] } },
                    avgRating: { $avg: '$rating' },
                    avgVerified: { $avg: { $cond: [{ $eq: ['$isVerifiedRating', true] }, '$rating', null] } },
                    star5: { $sum: { $cond: [{ $eq: ['$rating', 5] }, 1, 0] } },
                    star4: { $sum: { $cond: [{ $eq: ['$rating', 4] }, 1, 0] } },
                    star3: { $sum: { $cond: [{ $eq: ['$rating', 3] }, 1, 0] } },
                    star2: { $sum: { $cond: [{ $eq: ['$rating', 2] }, 1, 0] } },
                    star1: { $sum: { $cond: [{ $eq: ['$rating', 1] }, 1, 0] } }
                }
            }
        ]);

        const stats = statsAggregation.length > 0 ? statsAggregation[0] : {
            totalReviews: 0, totalVerified: 0, avgRating: 0, avgVerified: 0,
            star5: 0, star4: 0, star3: 0, star2: 0, star1: 0
        };

        res.json({
            reviews,
            stats,
            pagination: {
                total,
                filteredTotal,
                page: parseInt(page),
                limit: parseInt(limit),
                totalPages: Math.ceil(filteredTotal / parseInt(limit))
            }
        });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});


// ═══════════════════════════════════════════════════════════
// Toggle Bookmark
// ═══════════════════════════════════════════════════════════
router.put('/:id/bookmark', verify, async (req, res) => {
    try {
        const projectId = req.params.id;
        const userId = req.user._id;

        const user = await User.findById(userId);
        const index = user.bookmarks.indexOf(projectId);

        if (index === -1) {
            user.bookmarks.push(projectId);
            await Project.findByIdAndUpdate(projectId, { $inc: { bookmarksCount: 1 } });
        } else {
            user.bookmarks.splice(index, 1);
            await Project.findByIdAndUpdate(projectId, { $inc: { bookmarksCount: -1 } });
        }

        await user.save();

        // Invalidate detail cache (bookmarksCount changed)
        invalidateProjectCaches(projectId).catch(() => {});

        res.json(user.bookmarks);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

module.exports = router;
